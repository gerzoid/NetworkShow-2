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
    private readonly ConcurrentDictionary<string, ConnectionAggregate> _connections = new();
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

        var key = $"{r.Protocol}|{localIp}:{localPort}|{remoteIp}:{remotePort}";
        bool created = false;
        var conn = _connections.GetOrAdd(key, k =>
        {
            created = true;
            return new ConnectionAggregate
            {
                Key = k,
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
                LastSeen = r.Timestamp
            };
        });

        conn.Packets++;
        conn.Bytes += r.Size;
        if (isInbound) conn.BytesIn += r.Size;
        else if (isOutbound) conn.BytesOut += r.Size;
        else conn.BytesIn += r.Size;
        conn.LastSeen = r.Timestamp;
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
        var ipEntry = _byIp.GetOrAdd(remoteIp, ip =>
        {
            ipCreated = true;
            return new RemoteIpAggregate
            {
                Ip = ip,
                Scope = IpClassifier.Classify(ip),
                FirstSeen = r.Timestamp,
                LastSeen = r.Timestamp
            };
        });
        ipEntry.Bytes += r.Size;
        if (isInbound) ipEntry.BytesIn += r.Size;
        else if (isOutbound) ipEntry.BytesOut += r.Size;
        else ipEntry.BytesIn += r.Size;
        ipEntry.Packets++;
        ipEntry.LastSeen = r.Timestamp;
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
        var procEntry = _byProcess.GetOrAdd(process, _ => new ProcessStats { Process = process });
        Interlocked.Add(ref procEntry.Bytes, r.Size);
        Interlocked.Increment(ref procEntry.Packets);
        Volatile.Write(ref procEntry.LastSeenTicks, DateTime.Now.Ticks);
    }

    public (long BytesIn, long BytesOut) SampleAndResetInterval()
    {
        long bIn = Interlocked.Exchange(ref _intervalIn, 0);
        long bOut = Interlocked.Exchange(ref _intervalOut, 0);
        return (bIn, bOut);
    }

    public IReadOnlyList<RemoteIpAggregate> TopIps(int count) =>
        _byIp.Values.OrderByDescending(x => x.Bytes).Take(count).ToList();

    public IReadOnlyDictionary<IpScope, long> BytesByScope()
    {
        var dict = new Dictionary<IpScope, long>();
        foreach (var ip in _byIp.Values)
        {
            dict.TryGetValue(ip.Scope, out var v);
            dict[ip.Scope] = v + ip.Bytes;
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
            if (kv.Value.LastSeen < cutoff && _connections.TryRemove(kv.Key, out var c))
            {
                removedConns ??= new List<ConnectionAggregate>();
                removedConns.Add(c);
            }
        }

        List<RemoteIpAggregate>? removedIps = null;
        foreach (var kv in _byIp)
        {
            if (kv.Value.LastSeen < cutoff && _byIp.TryRemove(kv.Key, out var ip))
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
