using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Производитель по MAC (база IEEE OUI из реестра Wireshark, встроена в программу — без сети).
/// Не работает для «случайных» (локально администрируемых) MAC: их генерируют телефоны и планшеты для приватности.
/// </summary>
public static class OuiDatabase
{
    private static Dictionary<string, string>? _map;
    private static readonly object Lock = new();

    /// <summary>Название производителя или пусто (случайный MAC / неизвестный префикс).</summary>
    public static string Lookup(string mac)
    {
        var hex = Normalize(mac);
        if (hex.Length < 6) return string.Empty;
        if (int.TryParse(hex.AsSpan(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var first) && (first & 0x02) != 0)
            return string.Empty; // локально администрируемый — производитель неизвестен

        var map = Load();
        // Сначала более длинные блоки (36 и 28 бит), затем стандартный OUI (24 бита)
        if (hex.Length >= 9 && map.TryGetValue(hex[..9], out var v36)) return v36;
        if (hex.Length >= 7 && map.TryGetValue(hex[..7], out var v28)) return v28;
        return map.TryGetValue(hex[..6], out var v24) ? v24 : string.Empty;
    }

    public static string Normalize(string mac)
    {
        Span<char> buf = stackalloc char[mac.Length];
        int n = 0;
        foreach (var c in mac)
            if (Uri.IsHexDigit(c)) buf[n++] = char.ToUpperInvariant(c);
        return new string(buf[..n]);
    }

    private static Dictionary<string, string> Load()
    {
        lock (Lock)
        {
            if (_map is not null) return _map;
            var map = new Dictionary<string, string>(60_000);
            try
            {
                using var raw = Assembly.GetExecutingAssembly().GetManifestResourceStream("oui.txt.gz");
                if (raw is not null)
                {
                    using var gz = new GZipStream(raw, CompressionMode.Decompress);
                    using var reader = new StreamReader(gz, System.Text.Encoding.UTF8);
                    string? line;
                    while ((line = reader.ReadLine()) is not null)
                    {
                        int tab = line.IndexOf('\t');
                        if (tab > 0) map[line[..tab]] = line[(tab + 1)..];
                    }
                }
            }
            catch { }
            _map = map;
            return map;
        }
    }
}
