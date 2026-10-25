using System;
using System.Buffers.Binary;

namespace NetworkMonitor.Helpers;

/// <summary>IP-адрес как значение: сравнение и хеш без аллокаций (ключ кэша строк/локальности).</summary>
public readonly record struct IpKey(ulong Hi, ulong Lo, bool IsV6)
{
    public static IpKey FromV4(ReadOnlySpan<byte> b) =>
        new(0, BinaryPrimitives.ReadUInt32BigEndian(b), false);

    public static IpKey FromV6(ReadOnlySpan<byte> b) =>
        new(BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]), true);
}

public struct PacketHeaders
{
    public IpKey Source;
    public IpKey Destination;
    /// <summary>Номер протокола транспортного уровня (IPv4 Protocol / последний IPv6 Next Header).</summary>
    public byte Protocol;
    public int SourcePort;
    public int DestinationPort;
    /// <summary>Смещение и длина полезной нагрузки TCP/UDP внутри кадра (0, если её нет).</summary>
    public int PayloadOffset;
    public int PayloadLength;

    public readonly bool IsTcp => Protocol == PacketHeaderParser.ProtoTcp;
    public readonly bool IsUdp => Protocol == PacketHeaderParser.ProtoUdp;
}

/// <summary>
/// Разбор заголовков L2–L4 прямо по байтам кадра, без построения дерева объектов
/// (замена Packet.ParsePacket на горячем пути захвата).
/// </summary>
public static class PacketHeaderParser
{
    public const byte ProtoTcp = 6;
    public const byte ProtoUdp = 17;

    // Значения PacketDotNet.LinkLayers
    private const int LinkNull = 0, LinkEthernet = 1, LinkRawLegacy = 12, LinkRaw = 101,
        LinkLoop = 108, LinkIPv4 = 228, LinkIPv6 = 229;

    /// <summary>Поддерживается ли тип канального уровня (иначе — разбор через PacketDotNet).</summary>
    public static bool SupportsLinkType(int linkType) => linkType is
        LinkNull or LinkEthernet or LinkRawLegacy or LinkRaw or LinkLoop or LinkIPv4 or LinkIPv6;

    /// <summary>false — кадр не IP (ARP и т.п.) или битый.</summary>
    public static bool TryParse(int linkType, ReadOnlySpan<byte> frame, out PacketHeaders h)
    {
        h = default;
        int ipOffset = linkType switch
        {
            LinkEthernet => EthernetIpOffset(frame),
            LinkNull or LinkLoop => frame.Length >= 4 ? 4 : -1, // 4 байта address family
            LinkRawLegacy or LinkRaw or LinkIPv4 or LinkIPv6 => 0,
            _ => -1
        };
        if (ipOffset < 0 || ipOffset >= frame.Length) return false;

        var ip = frame[ipOffset..];
        return (ip[0] >> 4) switch
        {
            4 => ParseV4(frame, ipOffset, ref h),
            6 => ParseV6(frame, ipOffset, ref h),
            _ => false
        };
    }

    private static int EthernetIpOffset(ReadOnlySpan<byte> f)
    {
        if (f.Length < 14) return -1;
        int pos = 12;
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(f[pos..]);
        // 802.1Q / 802.1ad (QinQ): каждый тег — 4 байта
        while (type is 0x8100 or 0x88A8)
        {
            pos += 4;
            if (pos + 2 > f.Length) return -1;
            type = BinaryPrimitives.ReadUInt16BigEndian(f[pos..]);
        }
        pos += 2;

        if (type is 0x0800 or 0x86DD) return pos;
        if (type == 0x8864) // PPPoE Session: 6 байт PPPoE + 2 байта PPP Protocol
        {
            if (pos + 8 > f.Length) return -1;
            ushort ppp = BinaryPrimitives.ReadUInt16BigEndian(f[(pos + 6)..]);
            return ppp is 0x0021 or 0x0057 ? pos + 8 : -1;
        }
        return -1;
    }

    private static bool ParseV4(ReadOnlySpan<byte> frame, int off, ref PacketHeaders h)
    {
        var ip = frame[off..];
        if (ip.Length < 20) return false;
        int ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > ip.Length) return false;

        // Total Length = 0 бывает при Large Send Offload — тогда берём весь кадр
        int total = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
        int end = total >= ihl && total <= ip.Length ? total : ip.Length;

        h.Protocol = ip[9];
        h.Source = IpKey.FromV4(ip[12..]);
        h.Destination = IpKey.FromV4(ip[16..]);

        // Не первый фрагмент: транспортного заголовка в нём нет
        bool laterFragment = (BinaryPrimitives.ReadUInt16BigEndian(ip[6..]) & 0x1FFF) != 0;
        return laterFragment || ParseTransport(frame, off + ihl, off + end, ref h);
    }

    private static bool ParseV6(ReadOnlySpan<byte> frame, int off, ref PacketHeaders h)
    {
        var ip = frame[off..];
        if (ip.Length < 40) return false;

        int payloadLen = BinaryPrimitives.ReadUInt16BigEndian(ip[4..]);
        int end = payloadLen > 0 && 40 + payloadLen <= ip.Length ? 40 + payloadLen : ip.Length;

        h.Source = IpKey.FromV6(ip[8..]);
        h.Destination = IpKey.FromV6(ip[24..]);

        byte next = ip[6];
        int pos = 40;
        // Пропуск extension headers; лимит итераций — защита от зацикленных пакетов
        for (int i = 0; i < 8; i++)
        {
            if (next is 0 or 43 or 60) // Hop-by-Hop, Routing, Destination Options
            {
                if (pos + 2 > end) break;
                next = ip[pos];
                pos += (ip[pos + 1] + 1) * 8;
            }
            else if (next == 44) // Fragment
            {
                if (pos + 8 > end) break;
                bool laterFragment = (BinaryPrimitives.ReadUInt16BigEndian(ip[(pos + 2)..]) & 0xFFF8) != 0;
                next = ip[pos];
                pos += 8;
                if (laterFragment) { h.Protocol = next; return true; }
            }
            else if (next == 51) // Authentication Header
            {
                if (pos + 2 > end) break;
                next = ip[pos];
                pos += (ip[pos + 1] + 2) * 4;
            }
            else break;
        }

        h.Protocol = next;
        return pos <= end && ParseTransport(frame, off + pos, off + end, ref h);
    }

    /// <summary>false — заголовок TCP/UDP обрезан.</summary>
    private static bool ParseTransport(ReadOnlySpan<byte> frame, int start, int end, ref PacketHeaders h)
    {
        if (h.Protocol == ProtoTcp)
        {
            if (start + 20 > end) return false;
            h.SourcePort = BinaryPrimitives.ReadUInt16BigEndian(frame[start..]);
            h.DestinationPort = BinaryPrimitives.ReadUInt16BigEndian(frame[(start + 2)..]);
            int dataOffset = (frame[start + 12] >> 4) * 4;
            if (dataOffset >= 20 && start + dataOffset <= end)
            {
                h.PayloadOffset = start + dataOffset;
                h.PayloadLength = end - h.PayloadOffset;
            }
        }
        else if (h.Protocol == ProtoUdp)
        {
            if (start + 8 > end) return false;
            h.SourcePort = BinaryPrimitives.ReadUInt16BigEndian(frame[start..]);
            h.DestinationPort = BinaryPrimitives.ReadUInt16BigEndian(frame[(start + 2)..]);
            h.PayloadOffset = start + 8;
            h.PayloadLength = end - h.PayloadOffset;
        }
        return true;
    }
}
