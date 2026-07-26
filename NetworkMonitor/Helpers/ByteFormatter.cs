using System.Globalization;

namespace NetworkMonitor.Helpers;

public static class ByteFormatter
{
    public static string Format(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double v = bytes;
        string[] units = { "KB", "MB", "GB", "TB" };
        int unit = -1;
        do
        {
            v /= 1024.0;
            unit++;
        } while (v >= 1024 && unit < units.Length - 1);
        return string.Create(CultureInfo.InvariantCulture, $"{v:F2} {units[unit]}");
    }

    public static string FormatRate(long bytesPerSecond) => Format(bytesPerSecond) + "/s";
}
