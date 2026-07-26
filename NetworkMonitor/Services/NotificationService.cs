using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using NetworkMonitor.Helpers;
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

    // Значения — время последнего появления: по нему Prune() удаляет
    // устаревшие записи, иначе словари растут неограниченно
    private readonly ConcurrentDictionary<string, DateTime> _knownIps = new();
    private readonly ConcurrentDictionary<string, DateTime> _warnedPorts = new();
    private readonly ConcurrentDictionary<string, DateTime> _blacklistLastWarn = new();

    private readonly ConcurrentDictionary<string, byte> _whitelist = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _blacklist = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cidrLock = new();
    private (IPAddress Network, int Prefix)[] _whitelistCidrs = Array.Empty<(IPAddress, int)>();
    private (IPAddress Network, int Prefix)[] _blacklistCidrs = Array.Empty<(IPAddress, int)>();

    private readonly Queue<long> _trafficSamples = new();
    private const int SampleWindow = 12;
    private long _lastIntervalBytes;
    private DateTime _lastSpikeNotification = DateTime.MinValue;
    private static readonly TimeSpan BlacklistRepeatInterval = TimeSpan.FromSeconds(30);

    public event EventHandler<TrafficNotification>? NotificationRaised;

    public IEnumerable<string> Whitelist => _whitelist.Keys;
    public IEnumerable<string> Blacklist => _blacklist.Keys;

    public void AddToWhitelist(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return;
        entry = entry.Trim();
        _whitelist[entry] = 0;
        TryAddCidr(entry, ref _whitelistCidrs);
    }

    public void AddToBlacklist(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return;
        entry = entry.Trim();
        _blacklist[entry] = 0;
        TryAddCidr(entry, ref _blacklistCidrs);
    }

    private void TryAddCidr(string entry, ref (IPAddress Network, int Prefix)[] target)
    {
        if (!entry.Contains('/')) return;
        if (!IpRangeHelper.TryParseCidr(entry, out var net, out var prefix)) return;
        lock (_cidrLock)
        {
            var current = System.Threading.Volatile.Read(ref target);
            if (current.Any(c => c.Network.Equals(net) && c.Prefix == prefix)) return;
            System.Threading.Volatile.Write(ref target, current.Append((net, prefix)).ToArray());
        }
    }

    private static bool Matches(ConcurrentDictionary<string, byte> exact,
        (IPAddress Network, int Prefix)[] cidrs, string ip)
    {
        if (exact.ContainsKey(ip)) return true;
        if (cidrs.Length == 0) return false;
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        foreach (var (net, prefix) in cidrs)
            if (IpRangeHelper.IsInCidr(addr, net, prefix)) return true;
        return false;
    }

    public void Inspect(PacketRecord r)
    {
        var remoteIp = r.Direction == TrafficDirection.Outbound ? r.DestinationIp : r.SourceIp;
        var now = DateTime.UtcNow;

        if (Matches(_blacklist, System.Threading.Volatile.Read(ref _blacklistCidrs), remoteIp))
        {
            var last = _blacklistLastWarn.GetValueOrDefault(remoteIp, DateTime.MinValue);
            if (now - last >= BlacklistRepeatInterval)
            {
                _blacklistLastWarn[remoteIp] = now;
                Raise(NotificationSeverity.Critical, "IP в чёрном списке",
                    $"Соединение с {remoteIp} ({r.ProcessName})");
            }
        }
        else if (!Matches(_whitelist, System.Threading.Volatile.Read(ref _whitelistCidrs), remoteIp))
        {
            if (_knownIps.TryAdd(remoteIp, now))
            {
                if (!IsLocalOrPrivate(remoteIp))
                {
                    Raise(NotificationSeverity.Info, "Новый внешний IP",
                        $"Первое соединение с {remoteIp} ({r.ProcessName})");
                }
            }
            else
            {
                _knownIps[remoteIp] = now;
            }
        }

        int remotePort = r.Direction == TrafficDirection.Outbound ? r.DestinationPort : r.SourcePort;
        if (SuspiciousPorts.Contains(remotePort))
        {
            var key = $"{remoteIp}:{remotePort}";
            if (_warnedPorts.TryAdd(key, now))
            {
                Raise(NotificationSeverity.Warning, "Подозрительный порт",
                    $"{r.Protocol} {remoteIp}:{remotePort} ({r.ProcessName})");
            }
            else
            {
                _warnedPorts[key] = now;
            }
        }
    }

    /// <summary>Удаляет записи, не встречавшиеся дольше <paramref name="ttl"/>.</summary>
    public void Prune(TimeSpan ttl)
    {
        var cutoff = DateTime.UtcNow - ttl;
        PruneDict(_knownIps, cutoff);
        PruneDict(_warnedPorts, cutoff);
        PruneDict(_blacklistLastWarn, cutoff);
    }

    private static void PruneDict(ConcurrentDictionary<string, DateTime> dict, DateTime cutoff)
    {
        foreach (var kv in dict)
        {
            if (kv.Value < cutoff)
                dict.TryRemove(kv.Key, out _);
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
                if ((DateTime.UtcNow - _lastSpikeNotification).TotalSeconds > 5)
                {
                    _lastSpikeNotification = DateTime.UtcNow;
                    Raise(NotificationSeverity.Warning, "Резкий рост трафика",
                        $"Текущий: {Format(bytesInInterval)}/s, средний: {Format(avg)}/s");
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
        if (ip.StartsWith("169.254.")) return true;
        if (ip.StartsWith("172."))
        {
            var parts = ip.Split('.');
            if (parts.Length > 1 && int.TryParse(parts[1], out var b) && b is >= 16 and <= 31) return true;
        }
        if (ip.StartsWith("100."))
        {
            // CGNAT 100.64.0.0/10
            var parts = ip.Split('.');
            if (parts.Length > 1 && int.TryParse(parts[1], out var b) && b is >= 64 and <= 127) return true;
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
