using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace NetworkMonitor.Helpers;

/// <summary>JA3: отпечаток TLS-клиента (версия, шифры, расширения, кривые) из ClientHello — отличает браузер, curl, Python и вредоносное ПО без расшифровки.</summary>
public static class Ja3Fingerprint
{
    /// <summary>Считает JA3 по TCP-данным, начинающимся с записи TLS handshake. Возвращает MD5 (hex) и исходную строку.</summary>
    public static bool TryCompute(ReadOnlySpan<byte> tls, out string hash, out string text)
    {
        hash = text = string.Empty;
        try
        {
            if (tls.Length < 48 || tls[0] != 0x16 || tls[5] != 0x01) return false;
            int pos = 9; // 5 (запись) + 4 (заголовок handshake)
            int version = (tls[pos] << 8) | tls[pos + 1];
            pos += 2 + 32;                                  // версия + random
            pos += 1 + tls[pos];                            // session id

            int csLen = (tls[pos] << 8) | tls[pos + 1];
            pos += 2;
            var ciphers = new List<int>();
            for (int i = 0; i + 1 < csLen && pos + i + 1 < tls.Length; i += 2)
            {
                int c = (tls[pos + i] << 8) | tls[pos + i + 1];
                if (!IsGrease(c)) ciphers.Add(c);
            }
            pos += csLen;
            pos += 1 + tls[pos];                            // сжатие

            var exts = new List<int>();
            var curves = new List<int>();
            var formats = new List<int>();
            if (pos + 2 <= tls.Length)
            {
                int extTotal = (tls[pos] << 8) | tls[pos + 1];
                pos += 2;
                int end = Math.Min(pos + extTotal, tls.Length);
                while (pos + 4 <= end)
                {
                    int type = (tls[pos] << 8) | tls[pos + 1];
                    int len = (tls[pos + 2] << 8) | tls[pos + 3];
                    pos += 4;
                    if (pos + len > tls.Length) len = tls.Length - pos;
                    if (!IsGrease(type))
                    {
                        exts.Add(type);
                        var d = tls.Slice(pos, len);
                        if (type == 10 && d.Length >= 2)            // supported_groups
                        {
                            for (int i = 2; i + 1 < d.Length; i += 2)
                            {
                                int g = (d[i] << 8) | d[i + 1];
                                if (!IsGrease(g)) curves.Add(g);
                            }
                        }
                        else if (type == 11 && d.Length >= 1)       // ec_point_formats
                        {
                            for (int i = 1; i < d.Length; i++) formats.Add(d[i]);
                        }
                    }
                    pos += len;
                }
            }

            text = $"{version},{string.Join("-", ciphers)},{string.Join("-", exts)},{string.Join("-", curves)},{string.Join("-", formats)}";
            hash = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(text))).ToLowerInvariant();
            return true;
        }
        catch { hash = text = string.Empty; return false; }
    }

    private static bool IsGrease(int v) => (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF);
}

/// <summary>Отпечатки JA3, замеченные у вредоносного ПО и управляющих серверов (список abuse.ch SSLBL). Встроен в программу.</summary>
public static class Ja3Blocklist
{
    private static Dictionary<string, string>? _map;
    private static readonly object Lock = new();

    /// <summary>Причина внесения в список (например, имя семейства) или null.</summary>
    public static string? Lookup(string hash)
    {
        if (string.IsNullOrEmpty(hash)) return null;
        return Load().TryGetValue(hash, out var reason) ? reason : null;
    }

    public static int Count => Load().Count;

    private static Dictionary<string, string> Load()
    {
        lock (Lock)
        {
            if (_map is not null) return _map;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var raw = Assembly.GetExecutingAssembly().GetManifestResourceStream("ja3_blocklist.csv");
                if (raw is not null)
                {
                    using var sr = new StreamReader(raw, Encoding.UTF8);
                    string? line;
                    while ((line = sr.ReadLine()) is not null)
                    {
                        if (line.Length == 0 || line[0] == '#') continue;
                        var parts = line.Split(',');
                        if (parts.Length >= 1 && parts[0].Length == 32)
                            map[parts[0]] = parts.Length > 3 ? parts[3].Trim() : "известный вредоносный отпечаток";
                    }
                }
            }
            catch { }
            _map = map;
            return map;
        }
    }
}
