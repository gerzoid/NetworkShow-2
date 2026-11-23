using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

[Collection("Settings")]
public class LogonCorrelationTests
{
    private long _now = 1_000_000;
    private DateTime _local = new(2026, 11, 23, 14, 0, 0);
    private readonly NotificationService _notify = new();
    private readonly List<TrafficNotification> _events = new();
    private readonly LogonMonitor _mon;

    public LogonCorrelationTests()
    {
        SettingsService.Persist = false;
        SettingsService.Current.Detection = new DetectionSettings();
        _notify.NotificationRaised += (_, n) => _events.Add(n);
        _mon = new LogonMonitor(_notify) { Clock = () => _now, LocalNow = () => _local };
    }

    private static Dictionary<string, string> D(params (string, string)[] kv) => kv.ToDictionary(x => x.Item1, x => x.Item2);
    private bool Has(string title) => _events.Any(e => e.Title == title);

    private void Fail(string ip, string user) => _mon.Process(4625, D(("LogonType", "3"), ("IpAddress", ip), ("TargetUserName", user)));
    private void Ok(string ip, string user, string type = "10") => _mon.Process(4624, D(("LogonType", type), ("IpAddress", ip), ("TargetUserName", user)));

    [Fact]
    public void SuccessAfterFailures_IsCritical_EvenFromLan()
    {
        for (int i = 0; i < 4; i++) { Fail("192.168.1.40", "gerz"); _now += 2000; }
        Ok("192.168.1.40", "gerz", "3");
        Assert.Contains(_events, e => e.Title == "Успешный вход после серии неудачных попыток" && e.Severity == NotificationSeverity.Critical);
    }

    [Fact]
    public void SuccessWithoutFailures_FromLanType3_IsIgnored_ExternalRdpCritical()
    {
        Ok("192.168.1.40", "gerz", "3");
        Assert.Empty(_events);
        Ok("8.8.8.8", "gerz", "10");
        Assert.Contains(_events, e => e.Title == "Вход в Windows по сети" && e.Severity == NotificationSeverity.Critical);
    }

    [Fact]
    public void LanRdp_WarnsByDay_CriticalAtNight()
    {
        Ok("192.168.1.40", "gerz", "10");
        Assert.Contains(_events, e => e.Severity == NotificationSeverity.Warning && e.Title == "Вход в Windows по сети");
        _events.Clear();
        _now += 2_000_000;
        _local = new DateTime(2026, 11, 23, 3, 0, 0);
        Ok("192.168.1.41", "gerz", "10");
        Assert.Contains(_events, e => e.Severity == NotificationSeverity.Critical && e.Message.Contains("тихие часы"));
    }

    [Fact]
    public void SystemEvents_NewUserAdminServiceTaskLogCleared()
    {
        _mon.Process(4720, D(("TargetUserName", "hacker"), ("SubjectUserName", "gerz")));
        Assert.True(Has("Создана учётная запись Windows"));
        _mon.Process(4732, D(("TargetSid", "S-1-5-32-544"), ("MemberSid", "S-1-5-21-1-2-3-1005"), ("MemberName", "-"), ("SubjectUserName", "gerz")));
        Assert.True(Has("Пользователь добавлен в администраторы"));
        _mon.Process(4732, D(("TargetSid", "S-1-5-32-545"), ("MemberSid", "S-1-5-21-1-2-3-1005")));      // не администраторы
        Assert.Single(_events, e => e.Title == "Пользователь добавлен в администраторы");
        _mon.Process(7045, D(("ServiceName", "evil"), ("ImagePath", @"C:\Users\x\evil.exe"), ("AccountName", "LocalSystem")));
        Assert.True(Has("Установлена новая служба Windows"));
        _mon.Process(1102, D(("SubjectUserName", "gerz")));
        Assert.True(Has("Журнал безопасности очищен"));
        _mon.Process(4740, D(("TargetUserName", "gerz"), ("TargetDomainName", "DESKTOP-X")));
        Assert.True(Has("Учётная запись заблокирована"));
    }

    [Fact]
    public void ScheduledTask_OnlyForeign_MicrosoftAndSystemIgnored()
    {
        _mon.Process(4698, D(("TaskName", @"\Microsoft\Windows\Defrag\ScheduledDefrag"), ("SubjectUserName", "SYSTEM")));
        _mon.Process(4698, D(("TaskName", @"\GoogleUpdateTaskMachine"), ("SubjectUserName", "DESKTOP$")));
        Assert.Empty(_events);
        _mon.Process(4698, D(("TaskName", @"\Updater"), ("SubjectUserName", "gerz")));
        Assert.True(Has("Создана задача планировщика"));
    }

    [Fact]
    public void BruteForce_Threshold()
    {
        for (int i = 0; i < 5; i++) Fail("1.2.3.4", "admin");
        Assert.True(Has("Подбор пароля Windows"));
    }
}
