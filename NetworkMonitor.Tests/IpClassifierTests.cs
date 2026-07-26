using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class IpClassifierTests
{
    [Theory]
    [InlineData("127.0.0.1", IpScope.Loopback)]
    [InlineData("10.1.2.3", IpScope.Private)]
    [InlineData("172.16.0.1", IpScope.Private)]
    [InlineData("172.31.255.255", IpScope.Private)]
    [InlineData("172.32.0.1", IpScope.Public)]
    [InlineData("192.168.1.1", IpScope.Private)]
    [InlineData("169.254.10.20", IpScope.LinkLocal)]
    [InlineData("224.0.0.1", IpScope.Multicast)]
    [InlineData("239.255.255.250", IpScope.Multicast)]
    [InlineData("8.8.8.8", IpScope.Public)]
    [InlineData("0.0.0.0", IpScope.Unknown)]
    [InlineData("::1", IpScope.Loopback)]
    [InlineData("fe80::1", IpScope.LinkLocal)]
    [InlineData("ff02::1", IpScope.Multicast)]
    [InlineData("fd00::1", IpScope.Private)]
    [InlineData("2001:4860:4860::8888", IpScope.Public)]
    [InlineData("::ffff:192.168.1.1", IpScope.Private)]
    [InlineData("::ffff:8.8.8.8", IpScope.Public)]
    [InlineData("not-an-ip", IpScope.Unknown)]
    [InlineData("", IpScope.Unknown)]
    public void Classify_ReturnsExpectedScope(string ip, IpScope expected)
    {
        Assert.Equal(expected, IpClassifier.Classify(ip));
    }
}
