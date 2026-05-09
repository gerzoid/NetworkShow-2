using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace NetworkMonitor.Services;

public sealed class ProcessResolverService : IDisposable
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    private static readonly TimeSpan EntryTtl = TimeSpan.FromSeconds(60);

    private readonly ConcurrentDictionary<string, Entry> _cache = new();
    private readonly ConcurrentDictionary<int, string> _pidNameCache = new();
    private readonly Timer _refreshTimer;
    private readonly Timer _pruneTimer;
    private readonly object _refreshLock = new();
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
        if (TryGet(protocol, srcIp, srcPort, out var v)) return (v.Pid, v.Name);
        if (TryGet(protocol, dstIp, dstPort, out v)) return (v.Pid, v.Name);
        if (TryGet(protocol, "0.0.0.0", srcPort, out v)) return (v.Pid, v.Name);
        if (TryGet(protocol, "0.0.0.0", dstPort, out v)) return (v.Pid, v.Name);
        if (TryGet(protocol, "::", srcPort, out v)) return (v.Pid, v.Name);
        if (TryGet(protocol, "::", dstPort, out v)) return (v.Pid, v.Name);
        return (0, "unknown");
    }

    private bool TryGet(string protocol, string ip, int port, out Entry entry)
    {
        var key = MakeKey(protocol, ip, port);
        return _cache.TryGetValue(key, out entry);
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
        }
        finally
        {
            Monitor.Exit(_refreshLock);
        }
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
    }

    private static string MakeKey(string protocol, string ip, int port) => $"{protocol}|{ip}|{port}";

    private void Upsert(string protocol, string ip, int port, int pid)
    {
        var name = PidToName(pid);
        var key = MakeKey(protocol, ip, port);
        _cache[key] = new Entry(pid, name, DateTime.UtcNow);
    }

    private string PidToName(int pid)
    {
        if (pid <= 0) return "system";
        if (pid == 4) return "System";
        if (_pidNameCache.TryGetValue(pid, out var name)) return name;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName;
        }
        catch
        {
            name = "unknown";
        }
        _pidNameCache[pid] = name;
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
