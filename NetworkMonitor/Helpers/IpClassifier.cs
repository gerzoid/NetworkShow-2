using System.Net;
using System.Net.Sockets;

namespace NetworkMonitor.Helpers;

public enum IpScope
{
    Unknown,
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Public
}

public static class IpClassifier
{
    public static IpScope Classify(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return IpScope.Unknown;
        if (!IPAddress.TryParse(ip, out var addr)) return IpScope.Unknown;
        return Classify(addr);
    }

    public static IpScope Classify(IPAddress addr)
    {
        if (addr.AddressFamily == AddressFamily.InterNetwork)
            return ClassifyV4(addr);
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
            return ClassifyV6(addr);
        return IpScope.Unknown;
    }

    public static bool IsLocal(IpScope scope) => scope != IpScope.Public && scope != IpScope.Unknown;

    private static IpScope ClassifyV4(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        if (b[0] == 127) return IpScope.Loopback;
        if (b[0] == 10) return IpScope.Private;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return IpScope.Private;
        if (b[0] == 192 && b[1] == 168) return IpScope.Private;
        if (b[0] == 169 && b[1] == 254) return IpScope.LinkLocal;
        if (b[0] >= 224 && b[0] <= 239) return IpScope.Multicast;
        if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return IpScope.Multicast;
        if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) return IpScope.Unknown;
        return IpScope.Public;
    }

    private static IpScope ClassifyV6(IPAddress addr)
    {
        if (IPAddress.IsLoopback(addr)) return IpScope.Loopback;
        var b = addr.GetAddressBytes();
        if (b[0] == 0xff) return IpScope.Multicast;
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return IpScope.LinkLocal;
        if ((b[0] & 0xfe) == 0xfc) return IpScope.Private;
        bool allZero = true;
        for (int i = 0; i < 10; i++) if (b[i] != 0) { allZero = false; break; }
        if (allZero && b[10] == 0xff && b[11] == 0xff)
        {
            var v4 = new IPAddress(new[] { b[12], b[13], b[14], b[15] });
            return ClassifyV4(v4);
        }
        return IpScope.Public;
    }

    public static string Display(IpScope scope) => scope switch
    {
        IpScope.Loopback => "Loopback",
        IpScope.Private => "LAN",
        IpScope.LinkLocal => "Link-local",
        IpScope.Multicast => "Multicast",
        IpScope.Public => "Internet",
        _ => "?"
    };
}
