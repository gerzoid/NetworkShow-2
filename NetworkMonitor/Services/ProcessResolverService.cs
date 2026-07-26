using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using NetworkMonitor.Helpers;

namespace NetworkMonitor.Services;

public sealed class ProcessResolverService : IDisposable
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    private static readonly TimeSpan EntryTtl = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MissRefreshDebounce = TimeSpan.FromMilliseconds(150);
    // Windows переиспользует PID — без TTL трафик нового процесса подписывался бы именем умершего
    private static readonly TimeSpan PidNameTtl = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, Entry> _cache = new();
    private readonly ConcurrentDictionary<int, (string Name, DateTime CachedAt)> _pidNameCache = new();
    private readonly SvchostServiceResolver _svchost = new();
    private readonly Timer _refreshTimer;
    private readonly Timer _pruneTimer;
    private readonly object _refreshLock = new();
    private long _lastRefreshTicks;
    private int _pendingMissRefresh;
    private volatile bool _disposed;

    private record struct Entry(int Pid, string Name, DateTime LastSeen);

    public ProcessResolverService()
    {
        Refresh();
        _refreshTimer = new Timer(_ => Refresh(), null, 1000, 1000);
        _pruneTimer = new Timer(_ => Prune(), null, 5000, 5000);
    }

    public (int Pid, string Name) ResolveConnection(string protocol, string srcIp, int srcPort, string dstIp, int dstPort)
    {
        if (TryResolveAll(protocol, srcIp, srcPort, dstIp, dstPort, out var hit))
            return (hit.Pid, hit.Name);

        TriggerMissRefresh();

        if (TryResolveAll(protocol, srcIp, srcPort, dstIp, dstPort, out hit))
            return (hit.Pid, hit.Name);

        var guess = PortServiceCatalog.LookupPair(protocol, srcPort, dstPort);
        if (!string.IsNullOrEmpty(guess))
            return (0, "~" + guess);

        return (0, "unknown");
    }

    private bool TryResolveAll(string protocol, string srcIp, int srcPort, string dstIp, int dstPort, out Entry entry)
    {
        if (TryGet(protocol, srcIp, srcPort, out entry)) return true;
        if (TryGet(protocol, dstIp, dstPort, out entry)) return true;
        if (TryGet(protocol, "0.0.0.0", srcPort, out entry)) return true;
        if (TryGet(protocol, "0.0.0.0", dstPort, out entry)) return true;
        if (TryGet(protocol, "::", srcPort, out entry)) return true;
        if (TryGet(protocol, "::", dstPort, out entry)) return true;
        return false;
    }

    private bool TryGet(string protocol, string ip, int port, out Entry entry)
    {
        var key = MakeKey(protocol, ip, port);
        return _cache.TryGetValue(key, out entry);
    }

    public void Upsert(string protocol, string ip, int port, int pid)
    {
        if (pid <= 0 || port <= 0 || string.IsNullOrEmpty(ip)) return;
        var name = PidToName(pid);
        var key = MakeKey(protocol, ip, port);
        _cache[key] = new Entry(pid, name, DateTime.UtcNow);
    }

    public void Refresh()
    {
        if (_disposed) return;
        if (!Monitor.TryEnter(_refreshLock)) return;
        try
        {
            try { LoadTcpTable(AF_INET); } catch { }
            try { LoadTcpTable(AF_INET6); } catch { }
            try { LoadUdpTable(AF_INET); } catch { }
            try { LoadUdpTable(AF_INET6); } catch { }
            Interlocked.Exchange(ref _lastRefreshTicks, DateTime.UtcNow.Ticks);
        }
        finally
        {
            Monitor.Exit(_refreshLock);
        }
    }

    private void TriggerMissRefresh()
    {
        if (_disposed) return;
        var lastTicks = Interlocked.Read(ref _lastRefreshTicks);
        var ageTicks = DateTime.UtcNow.Ticks - lastTicks;
        if (ageTicks < MissRefreshDebounce.Ticks) return;
        if (Interlocked.Exchange(ref _pendingMissRefresh, 1) == 1) return;

        Task.Run(() =>
        {
            try { Refresh(); }
            finally { Interlocked.Exchange(ref _pendingMissRefresh, 0); }
        });
    }

    private void Prune()
    {
        if (_disposed) return;
        var cutoff = DateTime.UtcNow - EntryTtl;
        foreach (var kv in _cache)
        {
            if (kv.Value.LastSeen < cutoff)
                _cache.TryRemove(kv.Key, out _);
        }

        var pidCutoff = DateTime.UtcNow - PidNameTtl;
        foreach (var kv in _pidNameCache)
        {
            if (kv.Value.CachedAt < pidCutoff)
                _pidNameCache.TryRemove(kv.Key, out _);
        }
    }

    private static string MakeKey(string protocol, string ip, int port) => $"{protocol}|{ip}|{port}";

    private string PidToName(int pid)
    {
        var baseName = GetBaseName(pid);
        if (string.Equals(baseName, "svchost", StringComparison.OrdinalIgnoreCase))
        {
            var services = _svchost.GetServices(pid);
            if (services.Count > 0)
                return $"svchost ({string.Join(", ", services)})";
        }
        return baseName;
    }

    private string GetBaseName(int pid)
    {
        if (pid < 0) return "system";
        if (pid == 0) return "system";
        if (pid == 4) return "System";
        if (_pidNameCache.TryGetValue(pid, out var cached) &&
            DateTime.UtcNow - cached.CachedAt < PidNameTtl)
            return cached.Name;

        var name = NativeProcess.TryGetProcessName(pid);
        if (string.IsNullOrEmpty(name))
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                name = p.ProcessName;
            }
            catch
            {
                _pidNameCache.TryRemove(pid, out _);
                return "unknown";
            }
        }

        if (string.IsNullOrEmpty(name)) return "unknown";
        _pidNameCache[pid] = (name, DateTime.UtcNow);
        return name;
    }

    private void LoadTcpTable(int family)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint status = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
            if (status != 0) return;
            int count = Marshal.ReadInt32(buffer);
            int offset = 4;
            if (family == AF_INET)
            {
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buffer + offset);
                    offset += rowSize;
                    var ip = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                    var port = SwapPort(row.localPort);
                    Upsert("TCP", ip, port, row.owningPid);
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(buffer + offset);
                    offset += rowSize;
                    var ip = new IPAddress(row.localAddr).ToString();
                    var port = SwapPort(row.localPort);
                    Upsert("TCP", ip, port, row.owningPid);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void LoadUdpTable(int family)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UDP_TABLE_OWNER_PID, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint status = GetExtendedUdpTable(buffer, ref size, false, family, UDP_TABLE_OWNER_PID, 0);
            if (status != 0) return;
            int count = Marshal.ReadInt32(buffer);
            int offset = 4;
            if (family == AF_INET)
            {
                int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(buffer + offset);
                    offset += rowSize;
                    var ip = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                    var port = SwapPort(row.localPort);
                    Upsert("UDP", ip, port, row.owningPid);
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(buffer + offset);
                    offset += rowSize;
                    var ip = new IPAddress(row.localAddr).ToString();
                    var port = SwapPort(row.localPort);
                    Upsert("UDP", ip, port, row.owningPid);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int SwapPort(uint p) => ((int)(p & 0xFF) << 8) | (int)((p >> 8) & 0xFF);

    public void Dispose()
    {
        _disposed = true;
        _refreshTimer.Dispose();
        _pruneTimer.Dispose();
        _svchost.Dispose();
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        public int owningPid;
    }
}
