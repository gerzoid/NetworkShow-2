using System.IO;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class NotificationLogReaderTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "ns-notif-" + Guid.NewGuid().ToString("N") + ".log");
    public void Dispose() { try { File.Delete(_path); } catch { } }

    [Fact]
    public void ReadsLastNotifications_NewestFirst()
    {
        File.WriteAllText(_path,
            "[2026-11-21T12:00:00.0000000+08:00] [Info] Новый внешний IP: Первое соединение с 1.2.3.4 (chrome)\r\n" +
            "[2026-11-21T12:05:00.0000000+08:00] [Warning] Подозрение на DNS-туннель: NetworkMonitor: x.arpa — 50 поддоменов\r\n" +
            "мусорная строка\r\n" +
            "[2026-11-21T12:10:00.0000000+08:00] [Critical] Сканирование портов: 8.8.8.8 обратился к 15 портам\r\n");

        var list = NotificationLogReader.ReadRecent(_path, 10);
        Assert.Equal(3, list.Count);
        Assert.Equal("Сканирование портов", list[0].Title);
        Assert.Equal(NotificationSeverity.Critical, list[0].Severity);
        Assert.Equal("Подозрение на DNS-туннель", list[1].Title);
        Assert.StartsWith("NetworkMonitor: x.arpa", list[1].Message); // двоеточие в сообщении не ломает заголовок
        Assert.Equal(NotificationSeverity.Info, list[2].Severity);
    }

    [Fact]
    public void LimitsToMaxAndHandlesMissingFile()
    {
        var lines = Enumerable.Range(0, 50).Select(i => $"[2026-11-21T12:{i:00}:00.0000000+08:00] [Info] T{i}: m");
        File.WriteAllLines(_path, lines);
        var list = NotificationLogReader.ReadRecent(_path, 5);
        Assert.Equal(5, list.Count);
        Assert.Equal("T49", list[0].Title);
        Assert.Empty(NotificationLogReader.ReadRecent(_path + ".nope", 5));
    }
}
