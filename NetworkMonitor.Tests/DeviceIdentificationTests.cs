using System.Text;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

[Collection("Settings")]
public class DeviceIdentificationTests
{
    [Theory]
    [InlineData("50-FF-20-ED-2C-A5", "Keenetic")]
    [InlineData("B0-02-47-9A-5C-27", "AMPAK")]
    [InlineData("3C:22:FB:00:11:22", "Apple")]
    public void Oui_ResolvesVendor(string mac, string expected) =>
        Assert.Contains(expected, OuiDatabase.Lookup(mac));

    [Fact]
    public void Oui_RandomMac_HasNoVendor() => Assert.Equal(string.Empty, OuiDatabase.Lookup("02-11-22-33-44-55"));

    private static byte[] Dhcp(string host, string vendorClass)
    {
        var p = new byte[240];
        p[0] = 1; p[1] = 1; p[2] = 6;
        var mac = new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22 };
        Array.Copy(mac, 0, p, 28, 6);
        p[236] = 0x63; p[237] = 0x82; p[238] = 0x53; p[239] = 0x63;
        var opts = new List<byte> { 53, 1, 1, 12, (byte)host.Length };
        opts.AddRange(Encoding.ASCII.GetBytes(host));
        opts.AddRange(new byte[] { 60, (byte)vendorClass.Length });
        opts.AddRange(Encoding.ASCII.GetBytes(vendorClass));
        opts.Add(255);
        return p.Concat(opts).ToArray();
    }

    [Fact]
    public void Dhcp_ExtractsHostnameVendorAndMac()
    {
        var hints = DeviceHintParser.Parse(68, 67, Dhcp("android-1a2b3c", "android-dhcp-13"), "0.0.0.0");
        Assert.Contains(hints, h => h.Kind == "hostname" && h.Text == "android-1a2b3c" && h.Mac == "AA-BB-CC-00-11-22");
        Assert.Contains(hints, h => h.Kind == "dhcp-vendor" && h.Text == "android-dhcp-13");
    }

    private static void Name(List<byte> b, string name)
    {
        foreach (var l in name.Split('.')) { b.Add((byte)l.Length); b.AddRange(Encoding.ASCII.GetBytes(l)); }
        b.Add(0);
    }

    [Fact]
    public void Mdns_ExtractsServiceNameAndHostIp()
    {
        var b = new List<byte> { 0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0 }; // ответ, 2 записи
        // PTR _googlecast._tcp.local -> Living Room-abc._googlecast._tcp.local
        Name(b, "_googlecast._tcp.local");
        b.AddRange(new byte[] { 0, 12, 0, 1, 0, 0, 0, 120 });
        var rd = new List<byte>(); Name(rd, "Living Room-abc._googlecast._tcp.local");
        b.Add(0); b.Add((byte)rd.Count); b.AddRange(rd);
        // A tv.local -> 192.168.1.50
        Name(b, "tv.local");
        b.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 50 });

        var hints = DeviceHintParser.Parse(5353, 5353, b.ToArray(), "192.168.1.50");
        Assert.Contains(hints, h => h.Kind == "service" && h.Text == "_googlecast._tcp");
        Assert.Contains(hints, h => h.Kind == "name" && h.Text == "Living Room-abc");
        Assert.Contains(hints, h => h.Kind == "mdns-host" && h.Ip == "192.168.1.50" && h.Text == "tv");
    }

    [Fact]
    public void Ssdp_ExtractsServerHeader()
    {
        var text = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nSERVER: Linux/4.9 UPnP/1.0 Samsung-TV/1.0\r\n\r\n";
        var hints = DeviceHintParser.Parse(50000, 1900, Encoding.ASCII.GetBytes(text), "192.168.1.60");
        Assert.Contains(hints, h => h.Kind == "ssdp-server" && h.Text.Contains("Samsung-TV"));
        Assert.Contains(hints, h => h.Kind == "ssdp" && h.Text.Contains("MediaRenderer"));
    }

    [Theory]
    [InlineData("AMPAK Technology, Inc.", "", new string[0], false, false, "AMPAK")]
    [InlineData("", "", new[] { "служба: _googlecast._tcp" }, false, false, "Chromecast")]
    [InlineData("Samsung Electronics", "", new[] { "служба: _androidtvremote2._tcp" }, false, false, "Android TV")]
    [InlineData("TCL King Electrical", "", new string[0], false, false, "Телевизор")]
    [InlineData("Keenetic Limited", "", new string[0], true, false, "Роутер")]
    [InlineData("", "android-9f8e7d", new[] { "DHCP: android-dhcp-13" }, false, true, "Android")]
    [InlineData("", "", new string[0], false, true, "случайный MAC")]
    public void Classifier_GuessesType(string vendor, string host, string[] hints, bool gateway, bool random, string expectedPart) =>
        Assert.Contains(expectedPart, DeviceClassifier.Guess(vendor, host, hints, gateway, random));

    [Fact]
    public void Monitor_AppliesHintsToDevice()
    {
        SettingsService.Persist = false;
        SettingsService.Current.Detection = new DetectionSettings();
        SettingsService.Current.KnownDevices = new() { new() { Mac = "50-FF-20-ED-2C-A5" } };
        using var mon = new LanDeviceMonitor(new NotificationService())
        {
            Source = () => new List<ArpEntry> { new("192.168.1.60", "B0-02-47-9A-5C-27", false) }
        };
        mon.Start(autoPoll: false);
        mon.Poll();
        mon.AddHint(new DeviceHint("192.168.1.60", null, "service", "_googlecast._tcp"));
        mon.AddHint(new DeviceHint("192.168.1.60", null, "mdns-host", "Living-Room-TV"));
        var d = mon.Snapshot().Single();
        Assert.Contains("AMPAK", d.Vendor);
        Assert.Contains("Chromecast", d.DeviceType);
        Assert.Equal("Living-Room-TV", d.Name);
    }

    [Fact]
    public void LanConnection_FromUnknownDevice_RaisesInfo_TrustedIgnored()
    {
        SettingsService.Persist = false;
        SettingsService.Current.Detection = new DetectionSettings();
        SettingsService.Current.KnownProcesses = new() { "seed" };
        var notify = new NotificationService();
        var events = new List<TrafficNotification>();
        notify.NotificationRaised += (_, n) => events.Add(n);
        using var svc = new AnomalyDetectionService(notify)
        {
            LanLookup = ip => ip == "192.168.1.5" ? (true, "мой ПК") : (null, string.Empty)
        };
        svc.Start();
        PacketRecord P(string src) => new()
        {
            SourceIp = src, DestinationIp = "192.168.1.10", DestinationPort = 3389, Protocol = "TCP",
            Direction = TrafficDirection.Inbound, TcpFlags = 0x02, ProcessName = "x"
        };
        svc.Inspect(P("192.168.1.5"));
        Assert.Empty(events);
        svc.Inspect(P("192.168.1.77"));
        Assert.Contains(events, e => e.Title == "Подключение из локальной сети" && e.Severity == NotificationSeverity.Info);
    }
}
