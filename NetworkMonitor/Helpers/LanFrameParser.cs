using System;
using System.Net;
using System.Text;

namespace NetworkMonitor.Helpers;

public sealed record ArpFrame(bool IsReply, string SenderMac, string SenderIp, string TargetIp);
public sealed record DhcpServerMessage(string MessageType, string ServerIp, string SourceIp, string? OfferedIp, string? Router, string? Dns);
public sealed record NameResponse(string Protocol, string SourceIp, string Name);

/// <summary>Разбор кадров и датаграмм, нужных для обнаружения атак в локальной сети: ARP, ответы DHCP-серверов, ответы LLMNR/NBNS.</summary>
public static class LanFrameParser
{
    /// <summary>ARP из Ethernet-кадра (в том числе с меткой VLAN).</summary>
    public static bool TryParseArp(ReadOnlySpan<byte> f, out ArpFrame arp)
    {
        arp = null!;
        int o = 12;
        if (f.Length < 42) return false;
        if (f[o] == 0x81 && f[o + 1] == 0x00) o += 4; // 802.1Q
        if (f.Length < o + 2 + 28 || f[o] != 0x08 || f[o + 1] != 0x06) return false;
        o += 2;
        // htype=1 (Ethernet), ptype=0x0800 (IPv4), hlen=6, plen=4
        if (f[o] != 0 || f[o + 1] != 1 || f[o + 2] != 0x08 || f[o + 3] != 0 || f[o + 4] != 6 || f[o + 5] != 4) return false;
        int op = (f[o + 6] << 8) | f[o + 7];
        if (op is not (1 or 2)) return false;
        string smac = Mac(f.Slice(o + 8, 6));
        string sip = new IPAddress(f.Slice(o + 14, 4)).ToString();
        string tip = new IPAddress(f.Slice(o + 24, 4)).ToString();
        arp = new ArpFrame(op == 2, smac, sip, tip);
        return true;
    }

    /// <summary>Ответ DHCP-сервера (OFFER или ACK): кто ответил, какой адрес, шлюз и DNS выдаёт.</summary>
    public static bool TryParseDhcpServer(ReadOnlySpan<byte> p, string sourceIp, out DhcpServerMessage msg)
    {
        msg = null!;
        if (p.Length < 245 || p[0] != 2) return false; // BOOTREPLY
        if (p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63) return false;
        string? offered = p[16..20].ToArray() is { } y && (y[0] | y[1] | y[2] | y[3]) != 0 ? new IPAddress(y).ToString() : null;
        int type = 0; string? server = null, router = null, dns = null;
        int i = 240;
        while (i + 1 < p.Length)
        {
            byte tag = p[i++];
            if (tag == 255) break;
            if (tag == 0) continue;
            int len = p[i++];
            if (i + len > p.Length) break;
            switch (tag)
            {
                case 53 when len == 1: type = p[i]; break;
                case 54 when len == 4: server = new IPAddress(p.Slice(i, 4)).ToString(); break;
                case 3 when len >= 4: router = new IPAddress(p.Slice(i, 4)).ToString(); break;
                case 6 when len >= 4: dns = new IPAddress(p.Slice(i, 4)).ToString(); break;
            }
            i += len;
        }
        if (type is not (2 or 5)) return false;
        msg = new DhcpServerMessage(type == 2 ? "OFFER" : "ACK", server ?? sourceIp, sourceIp, offered, router, dns);
        return true;
    }

    /// <summary>Ответ LLMNR (порт 5355) или NBNS (137): какое имя «подтвердил» источник.</summary>
    public static bool TryParseNameResponse(int srcPort, ReadOnlySpan<byte> p, string sourceIp, out NameResponse r)
    {
        r = null!;
        if (p.Length < 17 || (p[2] & 0x80) == 0) return false; // нужен ответ (QR=1)
        if (srcPort == 5355)
        {
            int an = (p[6] << 8) | p[7];
            if (an == 0) return false;
            int pos = 12;
            var name = ReadLabels(p, ref pos);
            if (name.Length == 0) return false;
            r = new NameResponse("LLMNR", sourceIp, name);
            return true;
        }
        if (srcPort == 137)
        {
            // NBNS: в секции ответа имя закодировано в 32 символа «A»..«P» (первый уровень кодирования)
            int pos = 12;
            if (p[pos] != 0x20 || p.Length < pos + 1 + 32) return false;
            var sb = new StringBuilder(16);
            for (int k = 0; k < 15; k++)
            {
                int hi = p[pos + 1 + k * 2] - 'A', lo = p[pos + 2 + k * 2] - 'A';
                if (hi is < 0 or > 15 || lo is < 0 or > 15) return false;
                sb.Append((char)((hi << 4) | lo));
            }
            var name = sb.ToString().Trim();
            if (name.Length == 0) return false;
            r = new NameResponse("NBNS", sourceIp, name);
            return true;
        }
        return false;
    }

    private static string ReadLabels(ReadOnlySpan<byte> p, ref int pos)
    {
        var sb = new StringBuilder();
        while (pos < p.Length)
        {
            int len = p[pos++];
            if (len == 0) break;
            if ((len & 0xC0) != 0 || pos + len > p.Length) return string.Empty;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(p.Slice(pos, len)));
            pos += len;
        }
        return sb.ToString().ToLowerInvariant();
    }

    private static string Mac(ReadOnlySpan<byte> b)
    {
        var parts = new string[6];
        for (int i = 0; i < 6; i++) parts[i] = b[i].ToString("X2");
        return string.Join("-", parts);
    }
}
