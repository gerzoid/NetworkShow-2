using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class DnsQueryParserTests
{
    private static byte[] Query(string name, ushort qtype = 1, bool response = false)
    {
        var b = new List<byte> { 0x12, 0x34, (byte)(response ? 0x81 : 0x01), 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.'))
        {
            b.Add((byte)label.Length);
            b.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        b.Add(0);
        b.Add((byte)(qtype >> 8)); b.Add((byte)qtype); b.Add(0); b.Add(1);
        return b.ToArray();
    }

    [Fact]
    public void ParsesQueryName()
    {
        Assert.True(DnsQueryParser.TryParse(Query("WWW.Example.com", 28), out var name, out var qt));
        Assert.Equal("www.example.com", name);
        Assert.Equal(28, qt);
    }

    [Fact]
    public void RejectsResponses_AndGarbage()
    {
        Assert.False(DnsQueryParser.TryParse(Query("example.com", response: true), out _, out _));
        Assert.False(DnsQueryParser.TryParse(new byte[] { 1, 2, 3 }, out _, out _));
        var bad = Query("example.com");
        bad[12] = 0xC0; // указатель в вопросе
        Assert.False(DnsQueryParser.TryParse(bad, out _, out _));
    }

    [Fact]
    public void BaseDomain_SplitsLastTwoLabels()
    {
        Assert.Equal("example.com", DnsQueryParser.BaseDomain("a.b.example.com", out var sub));
        Assert.Equal("a.b", sub);
        Assert.Equal("example.com", DnsQueryParser.BaseDomain("example.com", out sub));
        Assert.Equal(string.Empty, sub);
    }

    [Fact]
    public void Entropy_RandomHigherThanWord()
    {
        Assert.True(DnsQueryParser.Entropy("xk3j9qz7vw2plm8r") > DnsQueryParser.Entropy("googlegoogle"));
    }

    [Fact]
    public void ThreatFeed_ParsesIpsAndSkipsComments()
    {
        var ips = ThreatFeedService.ParseIps("# comment\n1.2.3.4\r\n\nbad line\n5.6.7.8\n# END");
        Assert.Equal(2, ips.Count);
        Assert.Contains("1.2.3.4", ips);
    }

    [Fact]
    public void ThreatFeed_RaisesCriticalOnMatch()
    {
        var notify = new NotificationService();
        var events = new List<TrafficNotification>();
        notify.NotificationRaised += (_, n) => events.Add(n);
        notify.SetThreatFeed(new HashSet<string> { "5.6.7.8" });
        notify.Inspect(new PacketRecord { Direction = TrafficDirection.Outbound, DestinationIp = "5.6.7.8", SourceIp = "192.168.1.2", ProcessName = "x", Protocol = "TCP" });
        Assert.Contains(events, e => e.Severity == NotificationSeverity.Critical && e.Title.Contains("фида"));
    }
}

public class DnsMonitorTests
{
    [Fact]
    public void ParseResults_ExtractsIps()
    {
        var ips = DnsMonitorService.ParseResults("type: 5 cdn.example.net;93.184.216.34;2606:2800:220:1::1;");
        Assert.Equal(new[] { "93.184.216.34", "2606:2800:220:1::1" }, ips);
        Assert.Empty(DnsMonitorService.ParseResults(null));
        Assert.Empty(DnsMonitorService.ParseResults("0.0.0.0;"));
    }
}
