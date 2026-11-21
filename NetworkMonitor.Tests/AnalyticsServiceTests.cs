using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class AnalyticsServiceTests
{
    private static ConnectionAggregate Conn(string proto, string process, string remoteIp, long bytesIn, long bytesOut,
        string sni = "", string host = "", string service = "")
    {
        var c = new ConnectionAggregate
        {
            Protocol = proto, ProcessName = process, RemoteIp = remoteIp, RemotePort = 443, Service = service,
            RemoteScope = IpClassifier.Classify(remoteIp),
            FirstSeen = DateTime.Now.AddMinutes(-1)
        };
        c.Sni = sni;
        c.RemoteHost = host;
        c.BytesIn = bytesIn;
        c.BytesOut = bytesOut;
        c.Bytes = bytesIn + bytesOut;
        c.Packets = 10;
        c.LastSeen = DateTime.Now;
        return c;
    }

    [Fact]
    public void ByProtocol_GroupsAndComputesShare()
    {
        var conns = new List<ConnectionAggregate>
        {
            Conn("TCP", "a", "1.1.1.1", 600, 0, service: "HTTPS"),
            Conn("TCP", "b", "2.2.2.2", 200, 0, service: "HTTPS"),
            Conn("UDP", "a", "3.3.3.3", 200, 0, service: "DNS"),
        };
        var rows = AnalyticsService.ByProtocol(conns);
        Assert.Equal(2, rows.Count);
        Assert.Equal("TCP · HTTPS", rows[0].Name);
        Assert.Equal(2, rows[0].Connections);
        Assert.Equal(0.8, rows[0].Share, 3);
    }

    [Fact]
    public void BySite_OnlyNamedHosts_GroupsSubdomains()
    {
        var conns = new List<ConnectionAggregate>
        {
            Conn("TCP", "chrome", "1.1.1.1", 500, 100, sni: "www.example.com"),
            Conn("TCP", "chrome", "1.1.1.2", 100, 50, sni: "cdn.example.com"),
            Conn("TCP", "curl", "9.9.9.9", 999, 0),                              // без имени — не сайт
            Conn("TCP", "chrome", "8.8.8.8", 10, 10, host: "8.8.8.8"),           // «имя» = IP — не сайт
        };
        var rows = AnalyticsService.BySite(conns);
        var row = Assert.Single(rows);
        Assert.Equal("example.com", row.Name);
        Assert.Equal(2, row.Connections);
        Assert.Equal(750, row.Bytes);
        Assert.Equal("chrome", row.Extra);
    }

    [Fact]
    public void ByProcess_ListsProtocolsAndHosts()
    {
        var conns = new List<ConnectionAggregate>
        {
            Conn("TCP", "app", "1.1.1.1", 100, 0),
            Conn("UDP", "app", "2.2.2.2", 100, 0),
            Conn("TCP", "app", "1.1.1.1", 100, 0),
        };
        var row = Assert.Single(AnalyticsService.ByProcess(conns));
        Assert.Equal("TCP/UDP", row.Extra);
        Assert.Equal(2, row.Hosts);
        Assert.Equal(3, row.Connections);
    }

    [Fact]
    public void Filter_AppliesPeriodAndSkipsEmpty()
    {
        var old = Conn("TCP", "old", "1.1.1.1", 100, 0);
        old.LastSeen = DateTime.Now.AddHours(-2);
        var fresh = Conn("TCP", "fresh", "2.2.2.2", 100, 0);
        var empty = Conn("TCP", "empty", "3.3.3.3", 0, 0);
        var all = new[] { old, fresh, empty };
        Assert.Single(AnalyticsService.Filter(all, TimeSpan.FromHours(1)));
        Assert.Equal(2, AnalyticsService.Filter(all, null).Count);
    }

    [Fact]
    public void ByZone_SplitsInternetAndLan()
    {
        var conns = new List<ConnectionAggregate>
        {
            Conn("TCP", "chrome", "8.8.8.8", 900, 0),
            Conn("UDP", "svc", "192.168.1.1", 100, 0),
            Conn("UDP", "svc", "224.0.0.251", 100, 0),
        };
        var rows = AnalyticsService.ByZone(conns);
        Assert.Equal(new[] { "Internet", "LAN", "Multicast" }, rows.Select(r => r.Name).ToArray());
        Assert.Equal(0.818, rows[0].Share, 2);
    }

    [Theory]
    [InlineData("UDP", "8.8.8.8", 0, 53, "DNS")]
    [InlineData("UDP", "192.168.1.1", 68, 67, "DHCP")]
    [InlineData("UDP", "224.0.0.251", 5353, 5353, "Обнаружение имён (mDNS / LLMNR / NetBIOS)")]
    [InlineData("UDP", "239.255.255.250", 50000, 1900, "Обнаружение устройств (SSDP / WS-Discovery)")]
    [InlineData("Icmp", "8.8.8.8", 0, 0, "ICMP / IGMP (диагностика, группы)")]
    [InlineData("UDP", "100.64.1.1", 50000, 4000, "Сеть провайдера (CGNAT)")]
    [InlineData("UDP", "255.255.255.255", 50000, 4000, "Broadcast")]
    [InlineData("TCP", "8.8.8.8", 50000, 443, AnalyticsService.UserTraffic)]
    public void Categorize_ClassifiesServiceTraffic(string proto, string ip, int localPort, int remotePort, string expected)
    {
        var conn = new ConnectionAggregate { Protocol = proto, RemoteIp = ip, LocalPort = localPort, RemotePort = remotePort, RemoteScope = IpClassifier.Classify(ip) };
        Assert.Equal(expected, AnalyticsService.Categorize(conn));
    }

    [Theory]
    [InlineData("100.64.0.1", IpScope.CarrierNat)]
    [InlineData("100.127.255.255", IpScope.CarrierNat)]
    [InlineData("100.128.0.1", IpScope.Public)]
    [InlineData("255.255.255.255", IpScope.Broadcast)]
    public void Classify_CgnatAndBroadcast(string ip, IpScope expected) =>
        Assert.Equal(expected, IpClassifier.Classify(ip));
}
