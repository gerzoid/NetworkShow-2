using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class ByteFormatterTests
{
    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(512, "512 B")]
    [InlineData(1023, "1023 B")]
    [InlineData(1024, "1.00 KB")]
    [InlineData(1536, "1.50 KB")]
    [InlineData(1024L * 1024, "1.00 MB")]
    [InlineData(1024L * 1024 * 1024, "1.00 GB")]
    [InlineData(1024L * 1024 * 1024 * 1024, "1.00 TB")]
    public void Format_UsesInvariantCulture(long bytes, string expected)
    {
        Assert.Equal(expected, ByteFormatter.Format(bytes));
    }

    [Fact]
    public void FormatRate_AppendsPerSecondSuffix()
    {
        Assert.Equal("1.00 KB/s", ByteFormatter.FormatRate(1024));
    }
}
