using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace NetworkMonitor.Helpers;

/// <summary>Снимок таблицы TCP с адресами обоих концов и PID владельца (в отличие от кэша ProcessResolver, где только локальный конец).</summary>
internal static class TcpTableReader
{
    public readonly record struct Row(IPAddress LocalAddr, int LocalPort, IPAddress RemoteAddr, int RemotePort, int Pid);

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct Row4
    {
        public uint state, localAddr, localPort, remoteAddr, remotePort;
        public int pid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Row6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScope, localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
        public uint remoteScope, remotePort, state;
        public int pid;
    }

    public static List<Row> Read()
    {
        var result = new List<Row>();
        try { Load(AF_INET, result); } catch { }
        try { Load(AF_INET6, result); } catch { }
        return result;
    }

    private static void Load(int family, List<Row> result)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint status = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (status == ERROR_INSUFFICIENT_BUFFER) continue;
                if (status != 0) return;

                int count = Marshal.ReadInt32(buffer);
                int offset = 4;
                if (family == AF_INET)
                {
                    int rowSize = Marshal.SizeOf<Row4>();
                    for (int i = 0; i < count; i++, offset += rowSize)
                    {
                        var r = Marshal.PtrToStructure<Row4>(buffer + offset);
                        result.Add(new Row(new IPAddress(BitConverter.GetBytes(r.localAddr)), SwapPort(r.localPort),
                            new IPAddress(BitConverter.GetBytes(r.remoteAddr)), SwapPort(r.remotePort), r.pid));
                    }
                }
                else
                {
                    int rowSize = Marshal.SizeOf<Row6>();
                    for (int i = 0; i < count; i++, offset += rowSize)
                    {
                        var r = Marshal.PtrToStructure<Row6>(buffer + offset);
                        result.Add(new Row(new IPAddress(r.localAddr), SwapPort(r.localPort),
                            new IPAddress(r.remoteAddr), SwapPort(r.remotePort), r.pid));
                    }
                }
                return;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static int SwapPort(uint p) => ((int)(p & 0xFF) << 8) | (int)((p >> 8) & 0xFF);
}
