using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using NetworkMonitor.Models;

namespace NetworkMonitor.Helpers;

/// <summary>Таблица ARP Windows (GetIpNetTable) и активный ARP-запрос (SendARP) — без Npcap и без прав администратора.</summary>
internal static class ArpNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public int dwIndex;
        public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] bPhysAddr;
        public uint dwAddr;
        public int dwType; // 1 other, 2 invalid, 3 dynamic, 4 static
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint phyAddrLen);

    public static List<ArpEntry> Read()
    {
        var result = new List<ArpEntry>();
        int size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0) return result;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, false) != 0) return result;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_IPNETROW>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(buf + 4 + i * rowSize);
                if (row.dwType is not (3 or 4) || row.dwPhysAddrLen != 6) continue;
                result.Add(new ArpEntry(new IPAddress(row.dwAddr).ToString(), FormatMac(row.bPhysAddr), row.dwType == 4));
            }
        }
        catch { }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }

    /// <summary>Отправляет ARP-запрос и возвращает MAC ответившего (null — не ответил). Блокирует до ~3 с.</summary>
    public static string? Resolve(IPAddress ip)
    {
        try
        {
            var mac = new byte[6];
            uint len = 6;
            int rc = SendARP(BitConverter.ToUInt32(ip.GetAddressBytes(), 0), 0, mac, ref len);
            return rc == 0 && len == 6 ? FormatMac(mac) : null;
        }
        catch { return null; }
    }

    private static string FormatMac(byte[] b) => string.Join("-", Array.ConvertAll(b[..6], x => x.ToString("X2")));
}
