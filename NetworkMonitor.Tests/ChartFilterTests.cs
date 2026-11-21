using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class ChartFilterTests
{
    private static PacketRecord Pkt(string proc, string proto, int size, TrafficDirection dir) => new()
    {
        ProcessName = proc, Protocol = proto, Size = size, Direction = dir,
        SourceIp = "192.168.1.2", DestinationIp = "8.8.8.8", SourcePort = 5000, DestinationPort = 443, Timestamp = DateTime.Now
    };

    [Theory]
    [InlineData(null, "TCP", true)]
    [InlineData("TCP", "TCP", true)]
    [InlineData("TCP", "UDP", false)]
    [InlineData("ICMP", "IcmpV6", true)]
    [InlineData("ICMP", "Icmp", true)]
    [InlineData("OTHER", "Igmp", true)]
    [InlineData("OTHER", "TCP", false)]
    public void ProtocolMatches_Works(string? selected, string proto, bool expected) =>
        Assert.Equal(expected, AggregationService.ProtocolMatches(selected, proto));

    [Fact]
    public void FilteredInterval_CountsOnlyMatchingProcessAndProtocol()
    {
        var agg = new AggregationService();
        agg.SetChartFilter("chrome", "TCP");
        agg.Add(Pkt("chrome", "TCP", 1000, TrafficDirection.Inbound));
        agg.Add(Pkt("chrome", "UDP", 500, TrafficDirection.Inbound));   // другой протокол
        agg.Add(Pkt("firefox", "TCP", 700, TrafficDirection.Outbound)); // другой процесс
        agg.Add(Pkt("chrome", "TCP", 200, TrafficDirection.Outbound));

        var (bin, bout) = agg.SampleFilteredInterval();
        Assert.Equal(1000, bin);
        Assert.Equal(200, bout);
        Assert.Equal((0L, 0L), agg.SampleFilteredInterval()); // сброшено

        agg.SetChartFilter(null, "UDP");
        agg.Add(Pkt("any", "UDP", 300, TrafficDirection.Inbound));
        Assert.Equal((300L, 0L), agg.SampleFilteredInterval());
    }
}
