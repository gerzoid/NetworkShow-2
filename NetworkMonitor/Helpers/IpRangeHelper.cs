using System;
using System.Net;
using System.Net.Sockets;

namespace NetworkMonitor.Helpers;

public static class IpRangeHelper
{
    public static bool TryParseIPv4(string s, out long value)
    {
        value = 0;
        if (!IPAddress.TryParse(s, out var addr)) return false;
        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) return false;
        value = ((long)bytes[0] << 24) | ((long)bytes[1] << 16) | ((long)bytes[2] << 8) | bytes[3];
        return true;
    }

    public static bool InRange(string ip, string from, string to)
    {
        if (!TryParseIPv4(ip, out var v)) return false;
        if (!TryParseIPv4(from, out var lo)) return false;
        if (!TryParseIPv4(to, out var hi)) return false;
        if (lo > hi) (lo, hi) = (hi, lo);
        return v >= lo && v <= hi;
    }

    public static bool TryParseCidr(string s, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        if (string.IsNullOrWhiteSpace(s)) return false;
        int idx = s.IndexOf('/');
        if (idx <= 0 || idx == s.Length - 1) return false;
        if (!IPAddress.TryParse(s.AsSpan(0, idx), out var net)) return false;
        if (!int.TryParse(s.AsSpan(idx + 1), out prefix)) return false;
        int max = net.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        if (prefix < 0 || prefix > max) return false;
        network = net;
        return true;
    }

    public static bool IsInCidr(IPAddress addr, IPAddress network, int prefix)
    {
        if (addr.AddressFamily != network.AddressFamily) return false;
        var a = addr.GetAddressBytes();
        var n = network.GetAddressBytes();
        int fullBytes = prefix / 8;
        int remBits = prefix % 8;
        for (int i = 0; i < fullBytes; i++)
            if (a[i] != n[i]) return false;
        if (remBits > 0)
        {
            int mask = 0xFF << (8 - remBits);
            if ((a[fullBytes] & mask) != (n[fullBytes] & mask)) return false;
        }
        return true;
    }
}
