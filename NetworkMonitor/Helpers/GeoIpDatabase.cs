using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Страна и провайдер (ASN) по IP из встроенной офлайн-базы IP-to-Country / IP-to-ASN Lite от DB-IP.com
/// (лицензия CC BY 4.0, https://db-ip.com). Работает без сети; для IPv6 точность до блока /32.
/// </summary>
public static class GeoIpDatabase
{
    private sealed class Tables
    {
        public uint[] C4Start = Array.Empty<uint>(); public ushort[] C4Val = Array.Empty<ushort>();
        public uint[] C6Start = Array.Empty<uint>(); public ushort[] C6Val = Array.Empty<ushort>();
        public uint[] A4Start = Array.Empty<uint>(); public uint[] A4Val = Array.Empty<uint>();
        public uint[] A6Start = Array.Empty<uint>(); public uint[] A6Val = Array.Empty<uint>();
        public Dictionary<uint, string> Orgs = new();
    }

    private static volatile Tables? _tables;
    private static int _loading;
    private static readonly ConcurrentDictionary<string, (string Country, string Asn)> Cache = new();

    public static bool IsLoaded => _tables is not null;

    /// <summary>Загружает базу в фоне (около 100–300 мс); до окончания Lookup возвращает пустые значения.</summary>
    public static void PreloadAsync()
    {
        if (_tables is not null || Interlocked.Exchange(ref _loading, 1) == 1) return;
        _ = System.Threading.Tasks.Task.Run(() => { try { _tables = Load(); } catch { _tables = new Tables(); } });
    }

    /// <summary>Двухбуквенный код страны и «AS15169 Google LLC»; пусто, если неизвестно или база ещё грузится.</summary>
    public static (string Country, string Asn) Lookup(string ip)
    {
        var t = _tables;
        if (t is null || string.IsNullOrEmpty(ip)) return (string.Empty, string.Empty);
        if (Cache.TryGetValue(ip, out var hit)) return hit;
        if (!IPAddress.TryParse(ip, out var addr)) return (string.Empty, string.Empty);
        var result = Lookup(t, addr);
        if (Cache.Count > 50_000) Cache.Clear();
        Cache[ip] = result;
        return result;
    }

    /// <summary>Для тестов: загрузить синхронно.</summary>
    public static void EnsureLoaded() => _tables ??= Load();

    private static (string, string) Lookup(Tables t, IPAddress addr)
    {
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        string country = string.Empty, asn = string.Empty;
        uint asnNum = 0;
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            uint key = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            int i = Find(t.C4Start, key);
            if (i >= 0) country = Cc(t.C4Val[i]);
            int j = Find(t.A4Start, key);
            if (j >= 0) asnNum = t.A4Val[j];
        }
        else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = addr.GetAddressBytes();
            uint key = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            int i = Find(t.C6Start, key);
            if (i >= 0) country = Cc(t.C6Val[i]);
            int j = Find(t.A6Start, key);
            if (j >= 0) asnNum = t.A6Val[j];
        }
        if (asnNum != 0)
        {
            t.Orgs.TryGetValue(asnNum, out var org);
            asn = string.IsNullOrEmpty(org) ? $"AS{asnNum}" : $"AS{asnNum} {org}";
        }
        return (country, asn);
    }

    private static string Cc(ushort v)
    {
        if (v == 0) return string.Empty;
        var cc = new string(new[] { (char)(v >> 8), (char)(v & 0xFF) });
        return cc == "ZZ" ? string.Empty : cc; // ZZ — зарезервированные и частные диапазоны
    }

    /// <summary>Индекс последней записи со start ≤ key или -1.</summary>
    private static int Find(uint[] starts, uint key)
    {
        int lo = 0, hi = starts.Length - 1, ans = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (starts[mid] <= key) { ans = mid; lo = mid + 1; } else hi = mid - 1;
        }
        return ans;
    }

    private static Tables Load()
    {
        var t = new Tables();
        using var raw = Assembly.GetExecutingAssembly().GetManifestResourceStream("geoipdb.gz");
        if (raw is null) return t;
        using var gz = new GZipStream(raw, CompressionMode.Decompress);
        using var ms = new MemoryStream();
        gz.CopyTo(ms);
        var buf = ms.GetBuffer();
        int pos = 4; // "GEO1"

        ReadCountry(buf, ref pos, out t.C4Start, out t.C4Val);
        ReadCountry(buf, ref pos, out t.C6Start, out t.C6Val);
        ReadAsn(buf, ref pos, out t.A4Start, out t.A4Val);
        ReadAsn(buf, ref pos, out t.A6Start, out t.A6Val);

        int orgs = (int)Varint(buf, ref pos);
        for (int i = 0; i < orgs; i++)
        {
            uint asn = Varint(buf, ref pos);
            int len = (int)Varint(buf, ref pos);
            t.Orgs[asn] = Encoding.UTF8.GetString(buf, pos, len);
            pos += len;
        }
        return t;
    }

    private static void ReadCountry(byte[] b, ref int pos, out uint[] starts, out ushort[] vals)
    {
        int n = (int)Varint(b, ref pos);
        starts = new uint[n]; vals = new ushort[n];
        uint cur = 0;
        for (int i = 0; i < n; i++)
        {
            cur += Varint(b, ref pos);
            starts[i] = cur;
            ushort v = (ushort)((b[pos] << 8) | b[pos + 1]);
            pos += 2;
            vals[i] = v == (('-' << 8) | '-') ? (ushort)0 : v;
        }
    }

    private static void ReadAsn(byte[] b, ref int pos, out uint[] starts, out uint[] vals)
    {
        int n = (int)Varint(b, ref pos);
        starts = new uint[n]; vals = new uint[n];
        uint cur = 0;
        for (int i = 0; i < n; i++)
        {
            cur += Varint(b, ref pos);
            starts[i] = cur;
            vals[i] = Varint(b, ref pos);
        }
    }

    private static uint Varint(byte[] b, ref int pos)
    {
        uint result = 0; int shift = 0;
        while (true)
        {
            byte x = b[pos++];
            result |= (uint)(x & 0x7F) << shift;
            if ((x & 0x80) == 0) return result;
            shift += 7;
        }
    }
}
