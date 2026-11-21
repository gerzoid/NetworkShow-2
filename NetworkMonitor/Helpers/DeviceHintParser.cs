using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using NetworkMonitor.Models;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Разбор служебных пакетов, по которым можно понять, что за устройство в сети (только чтение, без запросов от нас):
///  • DHCP-запрос клиента — имя хоста (опция 12) и класс производителя (опция 60, у Android «android-dhcp-13»);
///  • mDNS — имя хоста, имена и типы служб (_googlecast, _airplay, _androidtvremote2…), TXT-модель;
///  • SSDP — строка SERVER устройства UPnP/DLNA.
/// </summary>
public static class DeviceHintParser
{
    public static bool IsCandidate(int srcPort, int dstPort) =>
        dstPort == 67 || srcPort == 5353 || dstPort == 5353 || srcPort == 1900 || dstPort == 1900;

    public static List<DeviceHint> Parse(int srcPort, int dstPort, ReadOnlySpan<byte> payload, string srcIp)
    {
        var list = new List<DeviceHint>();
        try
        {
            if (dstPort == 67 && srcPort == 68) ParseDhcp(payload, srcIp, list);
            else if (srcPort == 5353 || dstPort == 5353) ParseMdns(payload, srcIp, list);
            else if (srcPort == 1900 || dstPort == 1900) ParseSsdp(payload, srcIp, list);
        }
        catch { }
        return list;
    }

    // ───────────── DHCP ─────────────

    private static void ParseDhcp(ReadOnlySpan<byte> p, string srcIp, List<DeviceHint> list)
    {
        if (p.Length < 245 || p[0] != 1) return; // только запросы клиента
        if (p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63) return;
        int hlen = p[2];
        string? mac = hlen == 6 ? string.Join("-", Convert(p.Slice(28, 6))) : null;

        int i = 240;
        while (i + 1 < p.Length)
        {
            byte tag = p[i++];
            if (tag == 255) break;
            if (tag == 0) continue;
            int len = p[i++];
            if (i + len > p.Length) break;
            if (tag == 12 && len > 0) list.Add(new DeviceHint(srcIp, mac, "hostname", Ascii(p.Slice(i, len))));
            else if (tag == 60 && len > 0) list.Add(new DeviceHint(srcIp, mac, "dhcp-vendor", Ascii(p.Slice(i, len))));
            i += len;
        }
    }

    private static string[] Convert(ReadOnlySpan<byte> b)
    {
        var r = new string[b.Length];
        for (int i = 0; i < b.Length; i++) r[i] = b[i].ToString("X2");
        return r;
    }

    // ───────────── mDNS ─────────────

    private static void ParseMdns(ReadOnlySpan<byte> p, string srcIp, List<DeviceHint> list)
    {
        if (p.Length < 12) return;
        int qd = (p[4] << 8) | p[5];
        int total = ((p[6] << 8) | p[7]) + ((p[8] << 8) | p[9]) + ((p[10] << 8) | p[11]);
        if (total == 0 || total > 64) return; // только ответы/объявления
        int pos = 12;
        for (int q = 0; q < qd; q++)
        {
            ReadName(p, ref pos);
            pos += 4;
            if (pos > p.Length) return;
        }

        for (int r = 0; r < total && pos < p.Length; r++)
        {
            string name = ReadName(p, ref pos);
            if (pos + 10 > p.Length) return;
            int type = (p[pos] << 8) | p[pos + 1];
            int rdlen = (p[pos + 8] << 8) | p[pos + 9];
            pos += 10;
            if (pos + rdlen > p.Length) return;
            int rd = pos;

            switch (type)
            {
                case 1 when rdlen == 4: // A
                    list.Add(new DeviceHint(new IPAddress(p.Slice(rd, 4)).ToString(), null, "mdns-host", Trim(name)));
                    break;
                case 12: // PTR
                {
                    int tp = rd;
                    string target = ReadName(p, ref tp);
                    AddService(name, target, srcIp, list);
                    break;
                }
                case 33 when rdlen > 6: // SRV
                {
                    int tp = rd + 6;
                    string host = ReadName(p, ref tp);
                    AddService(string.Empty, name, srcIp, list);
                    list.Add(new DeviceHint(srcIp, null, "mdns-host", Trim(host)));
                    break;
                }
                case 16: // TXT
                    ParseTxt(p.Slice(rd, rdlen), srcIp, list);
                    break;
            }
            pos += rdlen;
        }
    }

    private static void AddService(string ptrName, string instanceFqdn, string srcIp, List<DeviceHint> list)
    {
        // PTR: _googlecast._tcp.local -> Living Room._googlecast._tcp.local
        string full = string.IsNullOrEmpty(instanceFqdn) ? ptrName : instanceFqdn;
        int us = full.IndexOf("._", StringComparison.Ordinal);
        if (us > 0)
        {
            list.Add(new DeviceHint(srcIp, null, "name", full[..us]));
            AddServiceType(full[(us + 1)..], srcIp, list);
        }
        else if (full.StartsWith('_'))
            AddServiceType(full, srcIp, list);
    }

    private static void AddServiceType(string svc, string srcIp, List<DeviceHint> list)
    {
        int d = svc.IndexOf(".local", StringComparison.OrdinalIgnoreCase);
        if (d > 0) svc = svc[..d];
        if (svc.StartsWith("_services", StringComparison.OrdinalIgnoreCase) || svc.Length < 4) return;
        list.Add(new DeviceHint(srcIp, null, "service", svc));
    }

    private static readonly HashSet<string> TxtKeys = new(StringComparer.OrdinalIgnoreCase)
        { "md", "fn", "model", "am", "ty", "product", "manufacturer", "deviceid", "usb_mdl", "rpmd" };

    private static void ParseTxt(ReadOnlySpan<byte> rd, string srcIp, List<DeviceHint> list)
    {
        int i = 0;
        while (i < rd.Length)
        {
            int len = rd[i++];
            if (len == 0 || i + len > rd.Length) break;
            string kv = Ascii(rd.Slice(i, len));
            int eq = kv.IndexOf('=');
            if (eq > 0 && TxtKeys.Contains(kv[..eq])) list.Add(new DeviceHint(srcIp, null, "model", kv));
            i += len;
        }
    }

    private static string ReadName(ReadOnlySpan<byte> p, ref int pos)
    {
        var sb = new StringBuilder();
        int cur = pos;
        bool jumped = false;
        for (int guard = 0; guard < 40 && cur < p.Length; guard++)
        {
            int len = p[cur];
            if (len == 0) { cur++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (cur + 1 >= p.Length) break;
                int ptr = ((len & 0x3F) << 8) | p[cur + 1];
                if (!jumped) { pos = cur + 2; jumped = true; }
                cur = ptr;
                continue;
            }
            cur++;
            if (cur + len > p.Length) break;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.UTF8.GetString(p.Slice(cur, len)));
            cur += len;
            if (sb.Length > 200) break;
        }
        if (!jumped) pos = cur;
        return sb.ToString();
    }

    private static string Trim(string host) =>
        host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ? host[..^6] : host;

    // ───────────── SSDP ─────────────

    private static void ParseSsdp(ReadOnlySpan<byte> p, string srcIp, List<DeviceHint> list)
    {
        if (p.Length < 20) return;
        string text = Encoding.ASCII.GetString(p[..Math.Min(p.Length, 700)]);
        if (text.StartsWith("M-SEARCH", StringComparison.Ordinal)) return; // запрос поиска, не объявление
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase))
                list.Add(new DeviceHint(srcIp, null, "ssdp-server", Cut(line[7..].Trim(), 80)));
            else if (line.StartsWith("NT:", StringComparison.OrdinalIgnoreCase) || line.StartsWith("ST:", StringComparison.OrdinalIgnoreCase))
            {
                var v = line[3..].Trim();
                if (v.Contains("MediaRenderer", StringComparison.OrdinalIgnoreCase)) list.Add(new DeviceHint(srcIp, null, "ssdp", "DLNA MediaRenderer"));
                else if (v.Contains("dial-multiscreen", StringComparison.OrdinalIgnoreCase)) list.Add(new DeviceHint(srcIp, null, "ssdp", "DIAL (YouTube/Netflix cast)"));
                else if (v.Contains("roku:ecp", StringComparison.OrdinalIgnoreCase)) list.Add(new DeviceHint(srcIp, null, "ssdp", "Roku"));
                else if (v.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase)) list.Add(new DeviceHint(srcIp, null, "ssdp", "роутер (UPnP IGD)"));
                else if (v.Contains("Printer", StringComparison.OrdinalIgnoreCase)) list.Add(new DeviceHint(srcIp, null, "ssdp", "принтер"));
            }
        }
    }

    private static string Cut(string s, int n) => s.Length <= n ? s : s[..n];

    private static string Ascii(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length);
        foreach (var x in b) if (x >= 0x20 && x < 0x7F) sb.Append((char)x);
        return sb.ToString();
    }
}
