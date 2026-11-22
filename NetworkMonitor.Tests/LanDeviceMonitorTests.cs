using System.Net;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

[Collection("Settings")]
public class LanDeviceMonitorTests : IDisposable
{
    private long _now = 1_000_000;
    private List<ArpEntry> _entries = new();
    private readonly NotificationService _notify = new();
    private readonly List<TrafficNotification> _events = new();
    private readonly LanDeviceMonitor _mon;

    public LanDeviceMonitorTests(bool learned = true)
    {
        SettingsService.Persist = false;
        SettingsService.Current.Detection = new DetectionSettings();
        SettingsService.Current.SeenDevices = new();
        SettingsService.Current.KnownDevices = new List<KnownDevice> { new() { Mac = "AA-AA-AA-AA-AA-01" } }; // нет «обучения»
        _notify.NotificationRaised += (_, n) => _events.Add(n);
        _mon = new LanDeviceMonitor(_notify) { Source = () => _entries, Clock = () => _now };
        _mon.Start(autoPoll: false);
    }

    public void Dispose() => _mon.Dispose();

    private bool Has(string title) => _events.Any(e => e.Title == title);

    [Fact]
    public void NewUnknownDevice_RaisesWarning()
    {
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-02", false) };
        _mon.Poll();
        Assert.True(Has("Новое устройство в сети"));
    }

    [Fact]
    public void KnownDevice_NoAlert()
    {
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-01", false) };
        _mon.Poll();
        Assert.Empty(_events);
    }

    [Fact]
    public void TrustedDevice_NotReported_Again()
    {
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-02", false) };
        _mon.Poll();
        _events.Clear();
        _mon.Trust("AA-AA-AA-AA-AA-02");
        _mon.Poll();
        Assert.Empty(_events);
        Assert.True(_mon.Snapshot().Single().IsKnown);
    }

    [Fact]
    public void Learning_FirstRun_TrustsSilently()
    {
        SettingsService.Current.SeenDevices = new();
        SettingsService.Current.KnownDevices = new();
        using var mon = new LanDeviceMonitor(_notify) { Source = () => _entries, Clock = () => _now };
        mon.Start(autoPoll: false);
        _entries = new() { new("192.168.1.10", "BA-BB-BB-BB-BB-01", false) };
        mon.Poll();
        Assert.Empty(_events);
        Assert.True(mon.Snapshot().Single().IsKnown);

        _now += 11 * 60_000; // обучение закончилось
        _entries = new() { new("192.168.1.10", "BA-BB-BB-BB-BB-01", false), new("192.168.1.11", "BA-BB-BB-BB-BB-02", false) };
        mon.Poll();
        Assert.True(Has("Новое устройство в сети"));
    }

    [Fact]
    public void SameIpDifferentMac_RaisesConflict()
    {
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-01", false) };
        _mon.Poll();
        _now += 30_000;
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-09", false) };
        _mon.Poll();
        Assert.True(Has("Конфликт IP-адреса в сети"));
    }

    [Fact]
    public void MulticastAndPublicEntries_AreIgnored()
    {
        _entries = new()
        {
            new("224.0.0.22", "01-00-5E-00-00-16", true),
            new("192.168.1.255", "FF-FF-FF-FF-FF-FF", true),
            new("8.8.8.8", "AA-AA-AA-AA-AA-03", false),
        };
        _mon.Poll();
        Assert.Empty(_mon.Snapshot());
    }

    [Theory]
    [InlineData("02-11-22-33-44-55", true)]
    [InlineData("3C-22-FB-00-00-01", false)]
    [InlineData("DA-A1-19-00-00-01", true)]
    public void RandomMac_Detection(string mac, bool expected) => Assert.Equal(expected, LanDevice.IsRandom(mac));

    [Fact]
    public void HostsOf_Slash24_Gives253()
    {
        var hosts = LanDeviceMonitor.HostsOf(IPAddress.Parse("192.168.1.38"), IPAddress.Parse("255.255.255.0")).ToList();
        Assert.Equal(253, hosts.Count);
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.38"), hosts);
        Assert.Empty(LanDeviceMonitor.HostsOf(IPAddress.Parse("10.1.2.3"), IPAddress.Parse("255.0.0.0")));
    }

    [Fact]
    public void Inventory_Survives_Restart_WithoutNewDeviceAlert()
    {
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-02", false) }; // не доверенное
        _mon.Poll();
        _mon.AddHint(new DeviceHint("192.168.1.10", null, "hostname", "android-abc123"));
        Assert.True(Has("Новое устройство в сети"));
        _mon.Stop(); // сохраняет таблицу в настройки

        _events.Clear();
        using var again = new LanDeviceMonitor(_notify) { Source = () => new List<ArpEntry>(), Clock = () => _now };
        again.Start(autoPoll: false);
        var restored = again.Snapshot().Single();
        Assert.Equal("AA-AA-AA-AA-AA-02", restored.Mac);
        Assert.Equal("android-abc123", restored.Name);
        Assert.False(restored.IsOnline);
        Assert.False(restored.IsKnown);

        // тот же MAC снова виден в ARP — это не «новое» устройство
        var seenAgain = new LanDeviceMonitor(_notify) { Source = () => new List<ArpEntry> { new("192.168.1.10", "AA-AA-AA-AA-AA-02", false) }, Clock = () => _now };
        seenAgain.Start(autoPoll: false);
        seenAgain.Poll();
        Assert.False(Has("Новое устройство в сети"));
        Assert.True(seenAgain.Snapshot().Single().IsOnline);
        seenAgain.Dispose();
    }

    [Fact]
    public void Rename_SetsUserName_PersistsAndSurvivesHints()
    {
        _entries = new() { new("192.168.1.10", "AA-AA-AA-AA-AA-02", false) };
        _mon.Poll();
        _mon.Rename("AA-AA-AA-AA-AA-02", "Приставка в спальне");
        _mon.AddHint(new DeviceHint("192.168.1.10", null, "hostname", "android-abc")); // не должна перебить своё имя
        Assert.Equal("Приставка в спальне", _mon.Snapshot().Single().Name);
        Assert.Equal("Приставка в спальне", _mon.UserNameByIp("192.168.1.10"));
        Assert.Single(_mon.UserNamed());

        _mon.Stop();
        using var again = new LanDeviceMonitor(_notify) { Source = () => new List<ArpEntry>(), Clock = () => _now };
        again.Start(autoPoll: false);
        Assert.Equal("Приставка в спальне", again.Snapshot().Single().Name);
        Assert.Equal("Приставка в спальне", again.UserNameByIp("192.168.1.10"));
    }
}
