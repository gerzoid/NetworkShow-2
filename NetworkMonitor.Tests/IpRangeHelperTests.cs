using System.Net;
using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class IpRangeHelperTests
{
    [Theory]
    [InlineData("192.168.1.5", "192.168.1.1", "192.168.1.10", true)]
    [InlineData("192.168.1.5", "192.168.1.10", "192.168.1.1", true)] // границы перепутаны — нормализуются
    [InlineData("192.168.2.5", "192.168.1.1", "192.168.1.10", false)]
    [InlineData("10.0.0.1", "10.0.0.1", "10.0.0.1", true)]
    [InlineData("not-an-ip", "10.0.0.1", "10.0.0.5", false)]
    public void InRange_Works(string ip, string from, string to, bool expected)
    {
        Assert.Equal(expected, IpRangeHelper.InRange(ip, from, to));
    }

    [Theory]
    [InlineData("192.168.0.0/24", true)]
    [InlineData("10.0.0.0/8", true)]
    [InlineData("2001:db8::/32", true)]
    [InlineData("192.168.0.0/33", false)]  // префикс больше 32 для IPv4
    [InlineData("192.168.0.0/-1", false)]
    [InlineData("192.168.0.0", false)]     // нет префикса
    [InlineData("/24", false)]
    [InlineData("abc/24", false)]
    [InlineData("", false)]
    public void TryParseCidr_ValidatesInput(string input, bool expected)
    {
        Assert.Equal(expected, IpRangeHelper.TryParseCidr(input, out _, out _));
    }

    [Theory]
    [InlineData("192.168.1.100", "192.168.1.0/24", true)]
    [InlineData("192.168.2.100", "192.168.1.0/24", false)]
    [InlineData("100.64.0.1", "100.64.0.0/10", true)]
    [InlineData("100.127.255.255", "100.64.0.0/10", true)]
    [InlineData("100.128.0.0", "100.64.0.0/10", false)]
    [InlineData("10.20.30.40", "0.0.0.0/0", true)]
    [InlineData("2001:db8::1", "2001:db8::/32", true)]
    [InlineData("2001:db9::1", "2001:db8::/32", false)]
    [InlineData("192.168.1.1", "2001:db8::/32", false)] // разные семейства адресов
    public void IsInCidr_Works(string ip, string cidr, bool expected)
    {
        Assert.True(IpRangeHelper.TryParseCidr(cidr, out var net, out var prefix));
        Assert.Equal(expected, IpRangeHelper.IsInCidr(IPAddress.Parse(ip), net, prefix));
    }
}
