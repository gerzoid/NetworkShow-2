using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Обнаружение атак и неисправностей в локальной сети по служебным кадрам (нужен захват пакетов):
///  • ответ DHCP от незнакомого сервера (поддельный DHCP, подмена шлюза и DNS);
///  • один источник «подтверждает» много разных имён по LLMNR/NBNS (признак атаки Responder);
///  • ARP: смена MAC у IP-адреса (ARP-подмена, конфликт адресов), особенно у шлюза; один MAC заявляет много адресов;
///  • ARP-сканирование: много запросов к разным адресам за короткое время.
/// Адреса из белого списка и собственные адреса/MAC игнорируются.
/// </summary>
public sealed class LanAttackDetector
{
    private readonly NotificationService _notify;
    private readonly object _gate = new();

    private readonly Dictionary<string, (string Mac, long Time)> _arpIpMac = new();
    private readonly Dictionary<string, (long Start, HashSet<string> Items)> _macClaims = new();
    private readonly Dictionary<string, (long Start, HashSet<string> Items)> _arpScan = new();
    private readonly Dictionary<string, (long Start, HashSet<string> Items)> _names = new();
    private readonly Dictionary<string, long> _alerted = new();

    private HashSet<string> _trustedDhcp = new();
    private HashSet<string> _gateways = new();
    private HashSet<string> _ownMacs = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _ownIps = new();
    private long _lastRefresh = long.MinValue / 2;

    public Func<long> Clock { get; set; } = () => Environment.TickCount64;

    /// <summary>Источник сведений о сетевых адаптерах (подменяется в тестах): доверенные DHCP-серверы, шлюзы, свои MAC и IP.</summary>
    internal Func<(HashSet<string> Dhcp, HashSet<string> Gateways, HashSet<string> Macs, HashSet<string> Ips)> NetworkInfo { get; set; } = ReadNics;

    public LanAttackDetector(NotificationService notify) => _notify = notify;

    private static DetectionSettings S => SettingsService.Current.Detection;

    public void OnDhcpServer(DhcpServerMessage m)
    {
        if (!S.Enabled) return;
        long now = Clock();
        lock (_gate)
        {
            Refresh(now);
            if (_trustedDhcp.Contains(m.ServerIp) || _gateways.Contains(m.ServerIp) || _ownIps.Contains(m.ServerIp)) return;
            if (_notify.IsWhitelisted(m.ServerIp)) return;
            if (!Once("dhcp|" + m.ServerIp, now, 3_600_000)) return;
        }
        _notify.RaiseExternal(NotificationSeverity.Critical, "Подозрительный DHCP-сервер",
            $"{m.ServerIp} ответил {m.MessageType} на запрос адреса" +
            (m.OfferedIp is null ? string.Empty : $" (выдаёт {m.OfferedIp}") +
            (m.Router is null ? string.Empty : $", шлюз {m.Router}") + (m.Dns is null ? string.Empty : $", DNS {m.Dns}") +
            (m.OfferedIp is null ? string.Empty : ")") +
            ". Обычно DHCP отвечает только роутер; посторонний сервер может перенаправить весь ваш трафик.");
    }

    public void OnNameResponse(NameResponse r)
    {
        if (!S.Enabled) return;
        long now = Clock();
        int count;
        lock (_gate)
        {
            Refresh(now);
            if (_ownIps.Contains(r.SourceIp) || _notify.IsWhitelisted(r.SourceIp)) return;
            count = Track(_names, r.SourceIp + "|" + r.Protocol, r.Name, now, 60_000);
            if (count < 5 || !Once("names|" + r.SourceIp, now, 600_000)) return;
        }
        _notify.RaiseExternal(NotificationSeverity.Critical, $"Подмена имён ({r.Protocol}): возможна атака Responder",
            $"{r.SourceIp} за минуту «подтвердил» {count} разных имён. Это признак поддельных ответов LLMNR/NBNS, которыми перехватывают хеши паролей Windows.");
    }

    public void OnArp(ArpFrame a)
    {
        if (!S.Enabled) return;
        long now = Clock();
        var alerts = new List<(NotificationSeverity, string, string)>();
        lock (_gate)
        {
            Refresh(now);
            bool ownMac = _ownMacs.Contains(a.SenderMac);

            // ARP-сканирование: запросы одного устройства к множеству разных адресов
            if (!a.IsReply && !ownMac && a.SenderIp != "0.0.0.0")
            {
                int n = Track(_arpScan, a.SenderMac, a.TargetIp, Clock(), 10_000);
                if (n >= 40 && Once("scan|" + a.SenderMac, now, 600_000))
                    alerts.Add((NotificationSeverity.Warning, "ARP-сканирование сети",
                        $"Устройство {a.SenderMac} ({a.SenderIp}) опросило {n} разных адресов за 10 с — так ищут устройства в сети."));
            }

            if (a.SenderIp == "0.0.0.0" || ownMac || _notify.IsWhitelisted(a.SenderIp)) goto done;

            // Смена MAC у IP-адреса
            if (_arpIpMac.TryGetValue(a.SenderIp, out var prev) && !prev.Mac.Equals(a.SenderMac, StringComparison.OrdinalIgnoreCase) && now - prev.Time < 300_000)
            {
                bool gw = _gateways.Contains(a.SenderIp);
                if (Once($"ip|{a.SenderIp}|{prev.Mac}|{a.SenderMac}", now, 600_000))
                    alerts.Add((gw ? NotificationSeverity.Critical : NotificationSeverity.Warning,
                        gw ? "ARP-подмена шлюза" : "ARP: у адреса сменился MAC",
                        $"{a.SenderIp} раньше отвечал с MAC {prev.Mac}, теперь с {a.SenderMac}" +
                        (gw ? " — типичный признак перехвата трафика (man-in-the-middle). Проверьте роутер и устройства сети." : ".")));
            }
            _arpIpMac[a.SenderIp] = (a.SenderMac, now);
            if (_arpIpMac.Count > 4096) _arpIpMac.Clear();

            // Один MAC заявляет много адресов
            int claims = Track(_macClaims, a.SenderMac, a.SenderIp, now, 60_000);
            if (claims >= 8 && Once("claims|" + a.SenderMac, now, 600_000))
                alerts.Add((NotificationSeverity.Warning, "ARP: одно устройство отвечает за много адресов",
                    $"MAC {a.SenderMac} заявил {claims} разных IP за минуту. Так делают при ARP-подмене; нормально только для роутеров, виртуализации и прокси-ARP."));
        done:;
        }
        foreach (var (sev, title, msg) in alerts) _notify.RaiseExternal(sev, title, msg);
    }

    // ───────────── Вспомогательное ─────────────

    private static int Track(Dictionary<string, (long Start, HashSet<string> Items)> map, string key, string item, long now, long windowMs)
    {
        if (!map.TryGetValue(key, out var e) || now - e.Start > windowMs)
        {
            if (map.Count > 4096) map.Clear();
            e = (now, new HashSet<string>());
            map[key] = e;
        }
        if (e.Items.Count < 256) e.Items.Add(item);
        return e.Items.Count;
    }

    private bool Once(string key, long now, long ttlMs)
    {
        if (_alerted.TryGetValue(key, out var last) && now - last < ttlMs) return false;
        if (_alerted.Count > 2048) _alerted.Clear();
        _alerted[key] = now;
        return true;
    }

    private void Refresh(long now)
    {
        if (now - _lastRefresh < 60_000) return;
        _lastRefresh = now;
        try
        {
            var (dhcp, gws, macs, ips) = NetworkInfo();
            _trustedDhcp = dhcp; _gateways = gws; _ownMacs = macs; _ownIps = ips;
        }
        catch { }
    }

    private static (HashSet<string>, HashSet<string>, HashSet<string>, HashSet<string>) ReadNics()
    {
        var dhcp = new HashSet<string>(); var gws = new HashSet<string>();
        var macs = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var ips = new HashSet<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var mac = nic.GetPhysicalAddress().GetAddressBytes();
            if (mac.Length == 6) macs.Add(string.Join("-", mac.Select(b => b.ToString("X2"))));
            var props = nic.GetIPProperties();
            foreach (var d in props.DhcpServerAddresses) if (d.AddressFamily == AddressFamily.InterNetwork) dhcp.Add(d.ToString());
            foreach (var g in props.GatewayAddresses) if (g.Address.AddressFamily == AddressFamily.InterNetwork) gws.Add(g.Address.ToString());
            foreach (var u in props.UnicastAddresses) if (u.Address.AddressFamily == AddressFamily.InterNetwork) ips.Add(u.Address.ToString());
        }
        return (dhcp, gws, macs, ips);
    }
}
