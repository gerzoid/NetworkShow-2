using System.Net;

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
}
