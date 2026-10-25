using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

public sealed class AggregationService
{
    // Структурный ключ: строковый ConnectionAggregate.Key собирается только при создании соединения
    private readonly record struct ConnectionKey(string Protocol, string LocalIp, int LocalPort, string RemoteIp, int RemotePort);

    private readonly ConcurrentDictionary<ConnectionKey, ConnectionAggregate> _connections = new();
    private readonly ConcurrentDictionary<string, RemoteIpAggregate> _byIp = new();
    private readonly ConcurrentDictionary<string, ProcessStats> _byProcess = new();

    private long _totalIn;
    private long _totalOut;
    private long _packetsTotal;
    private long _intervalIn;
    private long _intervalOut;

    public long TotalBytesIn => Interlocked.Read(ref _totalIn);
    public long TotalBytesOut => Interlocked.Read(ref _totalOut);
    public long TotalPackets => Interlocked.Read(ref _packetsTotal);

    public IEnumerable<ConnectionAggregate> Connections => _connections.Values;
    public IEnumerable<RemoteIpAggregate> RemoteIps => _byIp.Values;

    public event EventHandler<ConnectionAggregate>? ConnectionCreated;
    public event EventHandler<RemoteIpAggregate>? RemoteIpCreated;
    public event EventHandler<IReadOnlyList<ConnectionAggregate>>? ConnectionsPruned;
    public event EventHandler<IReadOnlyList<RemoteIpAggregate>>? RemoteIpsPruned;

    public void Add(PacketRecord r)
    {
        Interlocked.Increment(ref _packetsTotal);

        bool isInbound = r.Direction == TrafficDirection.Inbound;
        bool isOutbound = r.Direction == TrafficDirection.Outbound;

        if (isInbound)
        {
            Interlocked.Add(ref _totalIn, r.Size);
            Interlocked.Add(ref _intervalIn, r.Size);
        }
        else if (isOutbound)
        {
            Interlocked.Add(ref _totalOut, r.Size);
            Interlocked.Add(ref _intervalOut, r.Size);
        }
        else
        {
            Interlocked.Add(ref _totalIn, r.Size);
            Interlocked.Add(ref _intervalIn, r.Size);
        }

        string localIp, remoteIp;
        int localPort, remotePort;
        if (isOutbound)
        {
            localIp = r.SourceIp;
            localPort = r.SourcePort;
            remoteIp = r.DestinationIp;
            remotePort = r.DestinationPort;
        }
        else if (isInbound)
        {
            localIp = r.DestinationIp;
            localPort = r.DestinationPort;
            remoteIp = r.SourceIp;
            remotePort = r.SourcePort;
        }
        else
        {
            localIp = r.SourceIp;
            localPort = r.SourcePort;
            remoteIp = r.DestinationIp;
            remotePort = r.DestinationPort;
        }

        var key = new ConnectionKey(r.Protocol, localIp, localPort, remoteIp, remotePort);
        bool created = false;
        // TryGetValue + GetOrAdd(значение) вместо GetOrAdd(лямбда): лямбда с захватом
        // создавала бы замыкание на каждый пакет, даже когда соединение уже есть
        if (!_connections.TryGetValue(key, out var conn))
        {
            var fresh = new ConnectionAggregate
            {
                Key = $"{r.Protocol}|{localIp}:{localPort}|{remoteIp}:{remotePort}",
                LocalIp = localIp,
                LocalPort = localPort,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                Protocol = r.Protocol,
                Service = PortServiceCatalog.LookupPair(r.Protocol, localPort, remotePort),
                RemoteScope = IpClassifier.Classify(remoteIp),
                ProcessName = r.ProcessName,
                ProcessId = r.ProcessId,
                FirstSeen = r.Timestamp,
                LastSeen = r.Timestamp,
                LiveLastSeen = r.Timestamp // иначе Prune может удалить запись до первого инкремента
            };
            conn = _connections.GetOrAdd(key, fresh);
            created = ReferenceEquals(conn, fresh);
        }

        conn.LivePackets++;
        conn.LiveBytes += r.Size;
        if (isOutbound) conn.LiveBytesOut += r.Size;
        else conn.LiveBytesIn += r.Size;
        conn.LiveLastSeen = r.Timestamp;
        if (IsWeakName(conn.ProcessName) && IsStrongName(r.ProcessName))
        {
            conn.ProcessName = r.ProcessName;
            conn.ProcessId = r.ProcessId;
        }

        if (!string.IsNullOrEmpty(r.Sni) && string.IsNullOrEmpty(conn.Sni))
            conn.Sni = r.Sni!;

        if (created)
        {
            try { ConnectionCreated?.Invoke(this, conn); }
            catch { }
        }

        bool ipCreated = false;
        if (!_byIp.TryGetValue(remoteIp, out var ipEntry))
        {
            var fresh = new RemoteIpAggregate
            {
                Ip = remoteIp,
                Scope = IpClassifier.Classify(remoteIp),
                FirstSeen = r.Timestamp,
                LastSeen = r.Timestamp,
                LiveLastSeen = r.Timestamp // иначе Prune может удалить запись до первого инкремента
            };
            ipEntry = _byIp.GetOrAdd(remoteIp, fresh);
            ipCreated = ReferenceEquals(ipEntry, fresh);
        }
        ipEntry.LiveBytes += r.Size;
        if (isOutbound) ipEntry.LiveBytesOut += r.Size;
        else ipEntry.LiveBytesIn += r.Size;
        ipEntry.LivePackets++;
        ipEntry.LiveLastSeen = r.Timestamp;
        if (created) ipEntry.Connections++;
        if (IsWeakName(ipEntry.TopProcess) && IsStrongName(r.ProcessName))
        {
            ipEntry.TopProcess = r.ProcessName;
            ipEntry.TopProcessId = r.ProcessId;
        }
        if (ipCreated)
        {
            try { RemoteIpCreated?.Invoke(this, ipEntry); }
            catch { }
        }

        var process = string.IsNullOrEmpty(r.ProcessName) ? "unknown" : r.ProcessName;
        if (!_byProcess.TryGetValue(process, out var procEntry))
            procEntry = _byProcess.GetOrAdd(process, new ProcessStats { Process = process });
        Interlocked.Add(ref procEntry.Bytes, r.Size);
        Interlocked.Increment(ref procEntry.Packets);
        Volatile.Write(ref procEntry.LastSeenTicks, r.Timestamp.Ticks); // локальное время, как в Prune
    }

    /// <summary>
    /// Переносит живые счётчики в привязанные свойства. Вызывается из UI-потока по таймеру:
    /// PropertyChanged — раз в тик на изменившуюся строку, а не на каждый пакет.
    /// </summary>
    public void PublishCounters()
    {
        // Перечисление ConcurrentDictionary без снимка (в отличие от .Values) — без блокировок и копии
        foreach (var kv in _connections) kv.Value.PublishCounters();
        foreach (var kv in _byIp) kv.Value.PublishCounters();
    }

    public (long BytesIn, long BytesOut) SampleAndResetInterval()
    {
        long bIn = Interlocked.Exchange(ref _intervalIn, 0);
        long bOut = Interlocked.Exchange(ref _intervalOut, 0);
        return (bIn, bOut);
    }

    public IReadOnlyList<RemoteIpAggregate> TopIps(int count) =>
        _byIp.Values.OrderByDescending(x => x.LiveBytes).Take(count).ToList();

    public IReadOnlyDictionary<IpScope, long> BytesByScope()
    {
        var dict = new Dictionary<IpScope, long>();
        foreach (var ip in _byIp.Values)
        {
            dict.TryGetValue(ip.Scope, out var v);
            dict[ip.Scope] = v + ip.LiveBytes;
        }
        return dict;
    }

    public IReadOnlyList<ProcessStats> TopProcesses(int count) =>
        _byProcess.Values.OrderByDescending(x => x.Bytes).Take(count).ToList();

    public void Prune(TimeSpan ttl)
    {
        var cutoff = DateTime.Now - ttl;

        List<ConnectionAggregate>? removedConns = null;
        foreach (var kv in _connections)
        {
            if (kv.Value.LiveLastSeen < cutoff && _connections.TryRemove(kv.Key, out var c))
            {
                removedConns ??= new List<ConnectionAggregate>();
                removedConns.Add(c);
            }
        }

        List<RemoteIpAggregate>? removedIps = null;
        foreach (var kv in _byIp)
        {
            if (kv.Value.LiveLastSeen < cutoff && _byIp.TryRemove(kv.Key, out var ip))
            {
                removedIps ??= new List<RemoteIpAggregate>();
                removedIps.Add(ip);
            }
        }

        // Счётчик соединений у IP инкрементируется при создании — корректируем при удалении
        if (removedConns is { Count: > 0 })
        {
            foreach (var c in removedConns)
            {
                if (_byIp.TryGetValue(c.RemoteIp, out var ipEntry) && ipEntry.Connections > 0)
                    ipEntry.Connections--;
            }
        }

        foreach (var kv in _byProcess)
        {
            if (Volatile.Read(ref kv.Value.LastSeenTicks) < cutoff.Ticks)
                _byProcess.TryRemove(kv.Key, out _);
        }

        if (removedConns is { Count: > 0 })
        {
            try { ConnectionsPruned?.Invoke(this, removedConns); } catch { }
        }
        if (removedIps is { Count: > 0 })
        {
            try { RemoteIpsPruned?.Invoke(this, removedIps); } catch { }
        }
    }

    private static bool IsWeakName(string? name) =>
        string.IsNullOrEmpty(name) || name == "unknown" || name.StartsWith('~');

    private static bool IsStrongName(string? name) =>
        !string.IsNullOrEmpty(name) && name != "unknown" && !name.StartsWith('~');

    public void Clear()
    {
        _connections.Clear();
        _byIp.Clear();
        _byProcess.Clear();
        Interlocked.Exchange(ref _totalIn, 0);
        Interlocked.Exchange(ref _totalOut, 0);
        Interlocked.Exchange(ref _packetsTotal, 0);
        Interlocked.Exchange(ref _intervalIn, 0);
        Interlocked.Exchange(ref _intervalOut, 0);
    }
}

public sealed class ProcessStats
{
    public string Process { get; init; } = string.Empty;
    public long Bytes;
    public long Packets;
    public long LastSeenTicks;
}
