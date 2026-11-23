using System;
using System.Collections.Generic;
using System.Linq;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>Дополнительные срезы аналитики: категории сайтов, страны, провайдеры (ASN), качество связи.</summary>
public static class AnalyticsExtras
{
    public const string None = "(не определено)";

    public static List<AnalyticsRow> BySiteCategory(IReadOnlyList<ConnectionAggregate> conns) =>
        Group(conns, c => string.IsNullOrEmpty(c.Category) ? None : c.Category);

    public static List<AnalyticsRow> ByCountry(IReadOnlyList<ConnectionAggregate> conns) =>
        Group(conns.Where(c => c.RemoteScope == Helpers.IpScope.Public).ToList(), c => string.IsNullOrEmpty(c.Country) ? None : c.Country);

    public static List<AnalyticsRow> ByAsn(IReadOnlyList<ConnectionAggregate> conns) =>
        Group(conns.Where(c => c.RemoteScope == Helpers.IpScope.Public).ToList(), c => string.IsNullOrEmpty(c.AsnText) ? None : c.AsnText);

    /// <summary>Качество связи по адресатам: средний RTT рукопожатия, доля повторных передач, сбросы. Только TCP с достаточным числом пакетов.</summary>
    public static List<AnalyticsRow> ByQuality(IReadOnlyList<ConnectionAggregate> conns)
    {
        return conns.Where(c => c.Protocol == "TCP" && c.Packets >= 20)
            .GroupBy(c => { var h = AnalyticsService.HostOf(c); return !string.IsNullOrEmpty(c.Alias) ? c.Alias : h.Length > 0 ? h : c.RemoteIp; })
            .Select(g =>
            {
                var list = g.OrderByDescending(c => c.Bytes).ToList();
                var rtts = list.Where(c => c.RttMs > 0).Select(c => c.RttMs).ToList();
                long packets = list.Sum(c => c.Packets);
                return new AnalyticsRow
                {
                    Name = g.Key,
                    Connections = list.Count,
                    Hosts = list.Select(c => c.RemoteIp).Distinct().Count(),
                    Packets = packets,
                    Bytes = list.Sum(c => c.Bytes),
                    BytesIn = list.Sum(c => c.BytesIn),
                    BytesOut = list.Sum(c => c.BytesOut),
                    AvgRttMs = rtts.Count > 0 ? rtts.Average() : 0,
                    RetransPercent = packets > 0 ? 100.0 * list.Sum(c => c.Retransmits) / packets : 0,
                    Resets = list.Sum(c => c.Resets),
                    FirstSeen = list.Min(c => c.FirstSeen),
                    LastSeen = list.Max(c => c.LastSeen),
                    Items = list.Take(500).ToList()
                };
            })
            .OrderByDescending(r => r.RetransPercent).ThenByDescending(r => r.AvgRttMs).Take(300).ToList();
    }

    private static List<AnalyticsRow> Group(IReadOnlyList<ConnectionAggregate> conns, Func<ConnectionAggregate, string> key)
    {
        long total = conns.Sum(c => c.Bytes);
        return conns.GroupBy(key).Select(g =>
        {
            var list = g.OrderByDescending(c => c.Bytes).ToList();
            long bytes = list.Sum(c => c.Bytes);
            return new AnalyticsRow
            {
                Name = g.Key,
                Extra = string.Join(", ", list.GroupBy(c => string.IsNullOrEmpty(c.ProcessName) ? "unknown" : c.ProcessName).OrderByDescending(p => p.Sum(c => c.Bytes)).Take(3).Select(p => p.Key)),
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
