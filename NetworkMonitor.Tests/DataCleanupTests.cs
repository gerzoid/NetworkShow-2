using System.IO;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class DataCleanupTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ns-cleanup-" + Guid.NewGuid().ToString("N"));
    private readonly DateTime _now = new(2026, 11, 21, 12, 0, 0);

    public DataCleanupTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private string Make(string name, int ageDays, string content = "x")
    {
        var p = Path.Combine(_dir, name);
        File.WriteAllText(p, content);
        File.SetLastWriteTime(p, _now.AddDays(-ageDays));
        return p;
    }

    [Fact]
    public void DeletesOnlyOlderFiles_OfSelectedKinds()
    {
        var oldTraffic = Make("traffic_20261001_000000.jsonl", 40);
        var newTraffic = Make("traffic_20261120_000000.jsonl", 1);
        var oldExport = Make("connections_20261001_000000.csv", 40);
        var oldAnalytics = Make("analytics_zones_20261001_000000.csv", 40);
        var crash = Make("crash.log", 40);

        var preview = DataCleanupService.Preview(_dir, TimeSpan.FromDays(30), CleanupKinds.TrafficLogs | CleanupKinds.Exports, _now);
        Assert.Equal(3, preview.Files);
        Assert.True(File.Exists(oldTraffic)); // предпросмотр ничего не удаляет

        var r = DataCleanupService.Execute(_dir, TimeSpan.FromDays(30), CleanupKinds.TrafficLogs | CleanupKinds.Exports, _now);
        Assert.Equal(3, r.Files);
        Assert.False(File.Exists(oldTraffic));
        Assert.False(File.Exists(oldExport));
        Assert.False(File.Exists(oldAnalytics));
        Assert.True(File.Exists(newTraffic));
        Assert.True(File.Exists(crash)); // crash.log не выбран
    }

    [Fact]
    public void AllData_DeletesEverythingSelected()
    {
        Make("traffic_a.jsonl", 0);
        Make("crash.log", 0);
        var r = DataCleanupService.Execute(_dir, null, CleanupKinds.All, _now);
        Assert.Equal(2, r.Files);
        Assert.Empty(Directory.GetFiles(_dir, "traffic_*"));
    }

    [Fact]
    public void NotificationLog_TrimsOldLinesKeepsRecent()
    {
        var log = Make("notifications.log", 0,
            "[2026-09-01T10:00:00.0000000+00:00] [Info] старое\r\n" +
            "[2026-11-20T10:00:00.0000000+00:00] [Warning] свежее\r\n" +
            "строка без даты\r\n");
        var r = DataCleanupService.Execute(_dir, TimeSpan.FromDays(30), CleanupKinds.NotificationLog, _now);
        Assert.Equal(1, r.NotificationLines);
        var text = File.ReadAllText(log);
        Assert.DoesNotContain("старое", text);
        Assert.Contains("свежее", text);
        Assert.Contains("без даты", text);
    }

    [Fact]
    public void LockedFile_IsSkipped_NotThrown()
    {
        var p = Make("traffic_busy.jsonl", 40);
        using var fs = new FileStream(p, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var r = DataCleanupService.Execute(_dir, TimeSpan.FromDays(30), CleanupKinds.TrafficLogs, _now);
        Assert.Equal(0, r.Files);
        Assert.Equal(1, r.Skipped);
    }

    [Fact]
    public void MissingDirectory_IsHarmless() =>
        Assert.Equal(0, DataCleanupService.Execute(Path.Combine(_dir, "nope"), null, CleanupKinds.All).Files);

    [Fact]
    public void AutostartTaskXml_ContainsHighestRunLevelAndArgs()
    {
        var xml = AutostartService.BuildTaskXml(@"PC\User & Co", @"C:\Apps\Network Show\NetworkMonitor.exe");
        Assert.Contains("<RunLevel>HighestAvailable</RunLevel>", xml);
        Assert.Contains("<LogonTrigger>", xml);
        Assert.Contains("--autostart", xml);
        Assert.Contains(@"C:\Apps\Network Show\NetworkMonitor.exe", xml);
        Assert.Contains("User &amp; Co", xml); // экранирование XML
        System.Xml.Linq.XDocument.Parse(xml); // корректный XML
    }
}
