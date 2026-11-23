using System.IO;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class HistoryStoreTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "ns-hist-" + Guid.NewGuid().ToString("N") + ".db");
    private readonly HistoryStore _store;

    public HistoryStoreTests()
    {
        _store = new HistoryStore(_path);
        _store.Open();
    }

    public void Dispose()
    {
        _store.Dispose();
        foreach (var f in new[] { _path, _path + "-wal", _path + "-shm" }) { try { File.Delete(f); } catch { } }
    }

    private static ConnectionAggregate Conn(string process, string ip, string sni, long bin, long bout, DateTime last, string country = "US", string category = "")
    {
        var c = new ConnectionAggregate { Key = "TCP|" + process + "|" + ip, Protocol = "TCP", ProcessName = process, RemoteIp = ip, RemotePort = 443, FirstSeen = last.AddMinutes(-5) };
        c.Sni = sni; c.Country = country; c.Category = category; c.AppProto = "tls";
        c.LiveBytes = bin + bout; c.LiveBytesIn = bin; c.LiveBytesOut = bout; c.LivePackets = 100; c.LiveLastSeen = last; c.LiveRttMs = 40; c.LiveRetransmits = 3;
        return c;
    }

    [Fact]
    public void SaveFlows_IsUpsert_AndQueryFilters()
    {
        var now = DateTime.Now;
        var c = Conn("chrome", "1.2.3.4", "www.youtube.com", 1000, 200, now, "US", "Стриминг");
        _store.SaveFlows(new[] { c, Conn("curl", "5.6.7.8", "", 10, 5, now.AddHours(-30)) });
        c.LiveBytesIn = 5000;       // тот же поток вырос — запись обновляется, а не дублируется
        _store.SaveFlows(new[] { c });

        var all = _store.QueryFlows(now.AddDays(-2), null);
        Assert.Equal(2, all.Count);
        Assert.Equal(5000, all.Single(r => r.Process == "chrome").BytesIn);
        Assert.Single(_store.QueryFlows(now.AddHours(-1), null));
        Assert.Single(_store.QueryFlows(now.AddDays(-2), "youtube"));
        Assert.Empty(_store.QueryFlows(now.AddDays(-2), "нет-такого"));
    }

    [Fact]
    public void Report_Aggregates_Flows_AndEvents()
    {
        var now = DateTime.Now;
        _store.SaveFlows(new[] { Conn("chrome", "1.2.3.4", "www.youtube.com", 9000, 1000, now, "US", "Стриминг"), Conn("tg", "9.9.9.9", "", 100, 100, now, "NL") });
        _store.SaveEvent(new TrafficNotification { Severity = NotificationSeverity.Critical, Title = "Сканирование портов", Message = "1.1.1.1", Timestamp = now });
        _store.SaveEvent(new TrafficNotification { Severity = NotificationSeverity.Info, Title = "Новое устройство в сети", Message = "x", Timestamp = now });

        var d = _store.BuildReport(now.AddDays(-7), now.AddMinutes(1));
        Assert.Equal(2, d.Flows);
        Assert.Equal(9100, d.TotalIn);
        Assert.Equal("chrome", d.Processes[0].Name);
        Assert.Equal("www.youtube.com", d.Sites[0].Name);
        Assert.Contains(d.Countries, x => x.Name == "NL");
        Assert.Equal(1, d.EventsBySeverity["Critical"]);
        Assert.Equal(1, d.NewDevices);
        Assert.Single(d.Important);

        var html = ReportService.BuildHtml(d);
        Assert.Contains("www.youtube.com", html);
        Assert.Contains("Сканирование портов", html);
    }

    [Fact]
    public void Purge_RemovesOld_AndCounts()
    {
        var now = DateTime.Now;
        _store.SaveFlows(new[] { Conn("a", "1.1.1.1", "", 10, 10, now.AddDays(-40)), Conn("b", "2.2.2.2", "", 10, 10, now) });
        var old = _store.CountOlderThan(now.AddDays(-30));
        Assert.Equal(1, old.Flows);
        _store.Purge(now.AddDays(-30));
        Assert.Single(_store.QueryFlows(now.AddDays(-100), null));
        _store.Purge(null);
        Assert.Empty(_store.QueryFlows(now.AddDays(-100), null));
    }
}
