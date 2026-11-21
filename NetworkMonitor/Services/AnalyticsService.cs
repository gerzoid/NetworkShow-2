using System;
using System.Collections.Generic;
using System.Linq;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Сводки по накопленным соединениям: по протоколам, сайтам и процессам.
/// Работает со снимком соединений (хранятся, пока не истекло время неактивности), поэтому «Всё время»
/// означает «всё, что ещё не удалено из списка соединений».
/// </summary>
public static class AnalyticsService
{
    /// <summary>Соединения с трафиком, активные в пределах периода (null — без ограничения).</summary>
    public static List<ConnectionAggregate> Filter(IEnumerable<ConnectionAggregate> all, TimeSpan? period)
    {
        var cutoff = period is null ? DateTime.MinValue : DateTime.Now - period.Value;
        return all.Where(c => c.Bytes > 0 && c.LastSeen >= cutoff).ToList();
    }

    public static List<AnalyticsRow> ByProtocol(IReadOnlyList<ConnectionAggregate> conns) =>
        Build(conns,
            c => string.IsNullOrEmpty(c.Service) ? c.Protocol : c.Protocol + " · " + c.Service,
            _ => string.Empty);

    public static List<AnalyticsRow> ByProcess(IReadOnlyList<ConnectionAggregate> conns) =>
        Build(conns,
            c => ProcessOf(c),
            g => string.Join("/", g.Select(c => c.Protocol).Distinct().OrderBy(p => p)));

    /// <summary>Зоны адресата: Internet, LAN, Multicast, Link-local, Loopback. Показывает, сколько трафика служебного/локального, а сколько внешнего.</summary>
    public static List<AnalyticsRow> ByZone(IReadOnlyList<ConnectionAggregate> conns) =>
        Build(conns, c => c.ScopeText, TopProcesses);

    /// <summary>
    /// Служебный и пользовательский трафик по категориям: DNS, DHCP, NTP, обнаружение устройств и имён,
    /// ICMP/IGMP, multicast/broadcast, сеть провайдера (CGNAT, TR-069). Всё остальное — «Пользовательский трафик».
    /// </summary>
    public static List<AnalyticsRow> ByCategory(IReadOnlyList<ConnectionAggregate> conns) =>
        Build(conns, Categorize, TopProcesses);

    public const string UserTraffic = "Пользовательский трафик";

    public static string Categorize(ConnectionAggregate c)
    {
        var proto = c.Protocol ?? string.Empty;
        if (proto.StartsWith("Icmp", StringComparison.OrdinalIgnoreCase) || proto.StartsWith("Igmp", StringComparison.OrdinalIgnoreCase))
            return "ICMP / IGMP (диагностика, группы)";

        bool Port(int p) => c.LocalPort == p || c.RemotePort == p;
        if (Port(53)) return "DNS";
        if (Port(67) || Port(68) || Port(546) || Port(547)) return "DHCP";
        if (Port(123)) return "Время (NTP)";
        if (Port(5353) || Port(5355) || Port(137) || Port(138)) return "Обнаружение имён (mDNS / LLMNR / NetBIOS)";
        if (Port(1900) || Port(3702)) return "Обнаружение устройств (SSDP / WS-Discovery)";
        if (Port(7547)) return "Управление провайдера (TR-069)";

        return c.RemoteScope switch
        {
            IpScope.Multicast => "Multicast",
            IpScope.Broadcast => "Broadcast",
            IpScope.CarrierNat => "Сеть провайдера (CGNAT)",
            IpScope.LinkLocal => "Link-local",
            _ => UserTraffic
        };
    }

    private static string TopProcesses(List<ConnectionAggregate> g) =>
        string.Join(", ", g.GroupBy(ProcessOf).OrderByDescending(p => p.Sum(c => c.Bytes)).Take(3).Select(p => p.Key));

    /// <summary>Сайты — только домены, к которым был трафик; поддомены сворачиваются в registrable-часть (a.b.example.com → example.com).</summary>
    public static List<AnalyticsRow> BySite(IReadOnlyList<ConnectionAggregate> conns)
    {
        var named = conns.Where(c => HostOf(c).Length > 0).ToList();
        return Build(named,
            c => DnsQueryParser.BaseDomain(HostOf(c), out _),
            TopProcesses);
    }

    /// <summary>Имя хоста соединения: SNI, иначе DNS-имя; пусто, если имени нет (или это просто IP).</summary>
    public static string HostOf(ConnectionAggregate c)
    {
        var h = !string.IsNullOrEmpty(c.Sni)
            ? c.Sni
            : (!string.IsNullOrEmpty(c.RemoteHost) && c.RemoteHost != c.RemoteIp ? c.RemoteHost : string.Empty);
        if (h.Length == 0) return string.Empty;
        if (h.EndsWith('.')) h = h[..^1];
        h = h.ToLowerInvariant();
        return System.Net.IPAddress.TryParse(h, out _) ? string.Empty : h;
    }

    private static string ProcessOf(ConnectionAggregate c) =>
        string.IsNullOrEmpty(c.ProcessName) ? "unknown" : c.ProcessName;

    private static List<AnalyticsRow> Build(IReadOnlyList<ConnectionAggregate> conns,
        Func<ConnectionAggregate, string> key, Func<List<ConnectionAggregate>, string> extra)
    {
        long total = conns.Sum(c => c.Bytes);
        return conns.GroupBy(key).Select(g =>
        {
            var list = g.OrderByDescending(c => c.Bytes).ToList();
            long bytes = list.Sum(c => c.Bytes);
            return new AnalyticsRow
            {
                Name = g.Key,
                Extra = extra(list),
                Connections = list.Count,
                Hosts = list.Select(c => c.RemoteIp).Distinct().Count(),
                Packets = list.Sum(c => c.Packets),
                Bytes = bytes,
                BytesIn = list.Sum(c => c.BytesIn),
                BytesOut = list.Sum(c => c.BytesOut),
                Share = total > 0 ? (double)bytes / total : 0,
                FirstSeen = list.Min(c => c.FirstSeen),
                LastSeen = list.Max(c => c.LastSeen),
                Items = list.Take(500).ToList()
            };
        }).OrderByDescending(r => r.Bytes).ToList();
    }
}
