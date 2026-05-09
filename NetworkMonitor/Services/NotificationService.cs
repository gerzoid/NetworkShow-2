using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

public sealed class NotificationService
{
    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        23,    // telnet
        135,   // RPC
        139,   // NetBIOS
        445,   // SMB
        1433,  // MSSQL
        3389,  // RDP
        4444,  // common backdoor
        5900,  // VNC
        6667,  // IRC
        31337  // Back Orifice
    };

    private readonly ConcurrentDictionary<string, byte> _knownIps = new();
    private readonly ConcurrentDictionary<string, byte> _whitelist = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _blacklist = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _warnedPorts = new();
    private readonly ConcurrentDictionary<string, DateTime> _blacklistLastWarn = new();

    private readonly Queue<long> _trafficSamples = new();
    private const int SampleWindow = 12;
    private long _lastIntervalBytes;
    private DateTime _lastSpikeNotification = DateTime.MinValue;
    private static readonly TimeSpan BlacklistRepeatInterval = TimeSpan.FromSeconds(30);

    public event EventHandler<TrafficNotification>? NotificationRaised;

    public IEnumerable<string> Whitelist => _whitelist.Keys;
    public IEnumerable<string> Blacklist => _blacklist.Keys;

    public void AddToWhitelist(string ip)
    {
        if (!string.IsNullOrWhiteSpace(ip)) _whitelist[ip] = 0;
    }

    public void AddToBlacklist(string ip)
    {
        if (!string.IsNullOrWhiteSpace(ip)) _blacklist[ip] = 0;
    }

    public void Inspect(PacketRecord r)
    {
        var remoteIp = r.Direction == TrafficDirection.Outbound ? r.DestinationIp : r.SourceIp;

        if (_blacklist.ContainsKey(remoteIp))
        {
            var now = DateTime.Now;
            var last = _blacklistLastWarn.GetValueOrDefault(remoteIp, DateTime.MinValue);
            if (now - last >= BlacklistRepeatInterval)
            {
                _blacklistLastWarn[remoteIp] = now;
                Raise(NotificationSeverity.Critical, "IP в чёрном списке",
                    $"Соединение с {remoteIp} ({r.ProcessName})");
            }
        }
        else if (!_whitelist.ContainsKey(remoteIp) && _knownIps.TryAdd(remoteIp, 0))
        {
            if (!IsLocalOrPrivate(remoteIp))
            {
                Raise(NotificationSeverity.Info, "Новый внешний IP",
                    $"Первое соединение с {remoteIp} ({r.ProcessName})");
            }
        }

        int remotePort = r.Direction == TrafficDirection.Outbound ? r.DestinationPort : r.SourcePort;
        if (SuspiciousPorts.Contains(remotePort))
        {
            var key = $"{remoteIp}:{remotePort}";
            if (_warnedPorts.TryAdd(key, 0))
            {
                Raise(NotificationSeverity.Warning, "Подозрительный порт",
                    $"{r.Protocol} {remoteIp}:{remotePort} ({r.ProcessName})");
            }
        }
    }

    public void RecordTrafficSample(long bytesInInterval)
    {
        _lastIntervalBytes = bytesInInterval;
        _trafficSamples.Enqueue(bytesInInterval);
        if (_trafficSamples.Count > SampleWindow) _trafficSamples.Dequeue();

        if (_trafficSamples.Count >= SampleWindow)
        {
            long sum = 0;
            foreach (var s in _trafficSamples) sum += s;
            long avg = sum / _trafficSamples.Count;

            if (avg > 0 && bytesInInterval > avg * 4 && bytesInInterval > 1_000_000)
            {
                if ((DateTime.Now - _lastSpikeNotification).TotalSeconds > 5)
                {
                    _lastSpikeNotification = DateTime.Now;
                    Raise(NotificationSeverity.Warning, "Резкий рост трафика",
                        $"Текущий: {Format(bytesInInterval)}/c, средний: {Format(avg)}/c");
                }
            }
        }
    }

    private void Raise(NotificationSeverity severity, string title, string message)
    {
        NotificationRaised?.Invoke(this, new TrafficNotification
        {
            Severity = severity,
            Title = title,
            Message = message
        });
    }

    private static bool IsLocalOrPrivate(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return true;
        if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("127.")) return true;
        if (ip.StartsWith("172."))
        {
            var parts = ip.Split('.');
            if (parts.Length > 1 && int.TryParse(parts[1], out var b) && b is >= 16 and <= 31) return true;
        }
        if (ip.StartsWith("fe80:") || ip == "::1" || ip.StartsWith("fc") || ip.StartsWith("fd")) return true;
        if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "255.255.255.255") return true;
        return false;
    }

    private static string Format(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }
}
