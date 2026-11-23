using System;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Определение прикладного протокола по первым байтам данных, а не по номеру порта: SSH или RDP на нестандартном порту,
/// BitTorrent, WireGuard, OpenVPN, TLS на странных портах. Возвращает статические строки (без аллокаций) или null.
/// Это сигнатурный анализ первых пакетов, а не полноценный DPI: зашифрованное содержимое не разбирается.
/// </summary>
public static class ProtocolSniffer
{
    public const string Tls = "tls", Ssh = "ssh", Rdp = "rdp", Http = "http", BitTorrent = "bittorrent", WireGuard = "wireguard",
        OpenVpn = "openvpn", Smb = "smb", Ftp = "ftp", Smtp = "smtp", Pop3 = "pop3", Imap = "imap", Telnet = "telnet", Quic = "quic";

    public static string? Detect(bool tcp, int srcPort, int dstPort, ReadOnlySpan<byte> p)
    {
        if (p.Length < 4) return null;
        return tcp ? DetectTcp(p) : DetectUdp(p);
    }

    private static string? DetectTcp(ReadOnlySpan<byte> p)
    {
        // TLS: запись handshake (ClientHello = 1, ServerHello = 2), версия 3.x
        if (p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p.Length >= 6 && (p[5] == 0x01 || p[5] == 0x02)) return Tls;

        if (StartsWith(p, "SSH-")) return Ssh;

        // RDP: TPKT (03 00 len) + X.224 Connection Request (0xE0)
        if (p[0] == 0x03 && p[1] == 0x00 && p.Length >= 11 && p[5] == 0xE0) return Rdp;

        if (p[0] == 0x13 && p.Length >= 20 && StartsWith(p[1..], "BitTorrent protocol")) return BitTorrent;

        if (StartsWith(p, "GET ") || StartsWith(p, "POST") || StartsWith(p, "HEAD") || StartsWith(p, "PUT ") ||
            StartsWith(p, "HTTP/") || StartsWith(p, "DELE") || StartsWith(p, "OPTI") || StartsWith(p, "CONN") || StartsWith(p, "PATC"))
            return Http;

        // SMB: NetBIOS-заголовок (00 00 xx xx) и затем \xFFSMB / \xFESMB
        if (p.Length >= 8 && p[0] == 0x00 && (p[4] == 0xFF || p[4] == 0xFE) && p[5] == (byte)'S' && p[6] == (byte)'M' && p[7] == (byte)'B') return Smb;

        // OpenVPN поверх TCP: 2 байта длины и опкод P_CONTROL_HARD_RESET_CLIENT_V2/V3 (7 или 8 в старших 5 битах)
        if (p.Length >= 14 && ((p[0] << 8) | p[1]) == p.Length - 2 && ((p[2] >> 3) is 7 or 8)) return OpenVpn;

        if (p[0] == 0xFF && p[1] is 0xFB or 0xFC or 0xFD or 0xFE && p.Length < 64) return Telnet;

        if (StartsWith(p, "220 ") || StartsWith(p, "USER") || StartsWith(p, "PASS")) return Ftp;
        if (StartsWith(p, "EHLO") || StartsWith(p, "HELO") || StartsWith(p, "MAIL")) return Smtp;
        if (StartsWith(p, "+OK ")) return Pop3;
        if (StartsWith(p, "* OK")) return Imap;
        return null;
    }

    private static string? DetectUdp(ReadOnlySpan<byte> p)
    {
        // WireGuard: тип сообщения и три нулевых байта; фиксированные длины handshake
        if (p[1] == 0 && p[2] == 0 && p[3] == 0)
        {
            if (p[0] == 1 && p.Length == 148) return WireGuard;
            if (p[0] == 2 && p.Length == 92) return WireGuard;
            if (p[0] == 3 && p.Length == 64) return WireGuard;
            if (p[0] == 4 && p.Length >= 32 && p.Length % 16 == 0) return WireGuard;
        }

        // OpenVPN: опкод P_CONTROL_HARD_RESET_CLIENT_V2 (7) в старших 5 битах, короткий пакет
        if ((p[0] >> 3) == 7 && p.Length is >= 14 and <= 120) return OpenVpn;

        // BitTorrent DHT (bencode)
        if (StartsWith(p, "d1:ad") || StartsWith(p, "d1:rd") || StartsWith(p, "d1:eli")) return BitTorrent;

        // QUIC: длинный заголовок и известная версия (v1, v2, черновики)
        if ((p[0] & 0x80) != 0 && p.Length >= 1200 && p.Length >= 6 &&
            ((p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 1) || (p[1] == 0x6b && p[2] == 0x33 && p[3] == 0x43 && p[4] == 0xcf) || p[1] == 0xff))
            return Quic;
        return null;
    }

    /// <summary>
    /// Эвристика Tor: клиент Tor подключается к ретрансляторам по TLS со случайным именем вида www.xxxxxxxx.com / .net,
    /// без реального сайта. Это признак, но не доказательство.
    /// </summary>
    public static bool LooksLikeTorSni(string? sni)
    {
        if (string.IsNullOrEmpty(sni) || sni.Length < 12 || sni.Length > 40) return false;
        if (!sni.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) return false;
        bool tld = sni.EndsWith(".com", StringComparison.OrdinalIgnoreCase) || sni.EndsWith(".net", StringComparison.OrdinalIgnoreCase);
        if (!tld) return false;
        var mid = sni.AsSpan(4, sni.Length - 8);
        if (mid.Length < 8 || mid.Length > 20) return false;
        int letters = 0, digits = 0;
        foreach (var c in mid)
        {
            if (c is >= 'a' and <= 'z' or >= 'A' and <= 'Z') letters++;
            else if (c is >= '0' and <= '9') digits++;
            else return false; // настоящие имена обычно содержат дефис или точки
        }
        return letters + digits == mid.Length && letters >= 6;
    }

    private static bool StartsWith(ReadOnlySpan<byte> p, string ascii)
    {
        if (p.Length < ascii.Length) return false;
        for (int i = 0; i < ascii.Length; i++)
            if (p[i] != (byte)ascii[i]) return false;
        return true;
    }
}
