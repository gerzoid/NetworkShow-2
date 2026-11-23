using System.Net;
using System.Text;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

[Collection("Settings")]
public class LanAttackTests
{
    private long _now = 1_000_000;
    private readonly NotificationService _notify = new();
    private readonly List<TrafficNotification> _events = new();
    private readonly LanAttackDetector _det;

    public LanAttackTests()
    {
        SettingsService.Persist = false;
        SettingsService.Current.Detection = new DetectionSettings();
        _notify.NotificationRaised += (_, n) => _events.Add(n);
        _det = new LanAttackDetector(_notify)
        {
            Clock = () => _now,
            NetworkInfo = () => (new() { "192.168.1.1" }, new() { "192.168.1.1" }, new() { "AA-AA-AA-AA-AA-AA" }, new() { "192.168.1.38" })
        };
    }

    private bool Has(string title) => _events.Any(e => e.Title == title || e.Title.StartsWith(title));

    private static byte[] ArpFrame(int op, string smac, string sip, string tip)
    {
        var f = new List<byte>();
        f.AddRange(new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
        f.AddRange(smac.Split('-').Select(x => Convert.ToByte(x, 16)));
        f.AddRange(new byte[] { 0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, (byte)op });
        f.AddRange(smac.Split('-').Select(x => Convert.ToByte(x, 16)));
        f.AddRange(IPAddress.Parse(sip).GetAddressBytes());
        f.AddRange(new byte[6]);
        f.AddRange(IPAddress.Parse(tip).GetAddressBytes());
        return f.ToArray();
    }

    [Fact]
    public void ArpParser_ReadsRequestAndReply()
    {
        Assert.True(LanFrameParser.TryParseArp(ArpFrame(2, "11-22-33-44-55-66", "192.168.1.1", "192.168.1.38"), out var a));
        Assert.True(a.IsReply);
        Assert.Equal("11-22-33-44-55-66", a.SenderMac);
        Assert.Equal("192.168.1.1", a.SenderIp);
        Assert.False(LanFrameParser.TryParseArp(new byte[60], out _));
    }

    [Fact]
    public void GatewayMacChange_IsCritical_OtherIsWarning()
    {
        _det.OnArp(new ArpFrame(true, "11-22-33-44-55-66", "192.168.1.1", "192.168.1.38"));
        _now += 5000;
        _det.OnArp(new ArpFrame(true, "66-55-44-33-22-11", "192.168.1.1", "192.168.1.38"));
        Assert.Contains(_events, e => e.Title == "ARP-подмена шлюза" && e.Severity == NotificationSeverity.Critical);

        _det.OnArp(new ArpFrame(true, "11-22-33-44-55-01", "192.168.1.50", "192.168.1.38"));
        _now += 5000;
        _det.OnArp(new ArpFrame(true, "11-22-33-44-55-02", "192.168.1.50", "192.168.1.38"));
        Assert.Contains(_events, e => e.Title == "ARP: у адреса сменился MAC" && e.Severity == NotificationSeverity.Warning);
    }

    [Fact]
    public void ArpScan_Detected_OwnMacIgnored()
    {
        for (int i = 1; i <= 50; i++) _det.OnArp(new ArpFrame(false, "AA-AA-AA-AA-AA-AA", "192.168.1.38", $"192.168.1.{i}"));
        Assert.False(Has("ARP-сканирование сети"));
        for (int i = 1; i <= 50; i++) _det.OnArp(new ArpFrame(false, "DE-AD-BE-EF-00-01", "192.168.1.99", $"192.168.1.{i}"));
        Assert.True(Has("ARP-сканирование сети"));
    }

    [Fact]
    public void OneMacManyIps_Warns()
    {
        for (int i = 10; i < 20; i++) _det.OnArp(new ArpFrame(true, "DE-AD-BE-EF-00-02", $"192.168.1.{i}", "192.168.1.38"));
        Assert.True(Has("ARP: одно устройство отвечает за много адресов"));
    }

    private static byte[] DhcpReply(int type, string server)
    {
        var p = new byte[240];
        p[0] = 2; p[1] = 1; p[2] = 6;
        new byte[] { 192, 168, 1, 77 }.CopyTo(p, 16);
        p[236] = 0x63; p[237] = 0x82; p[238] = 0x53; p[239] = 0x63;
        var opts = new List<byte> { 53, 1, (byte)type, 54, 4 };
        opts.AddRange(IPAddress.Parse(server).GetAddressBytes());
        opts.AddRange(new byte[] { 3, 4, 10, 66, 66, 66, 6, 4, 8, 8, 8, 8, 255 });
        return p.Concat(opts).ToArray();
    }

    [Fact]
    public void RogueDhcp_Critical_TrustedRouterIgnored()
    {
        Assert.True(LanFrameParser.TryParseDhcpServer(DhcpReply(2, "192.168.1.99"), "192.168.1.99", out var rogue));
        Assert.Equal("OFFER", rogue.MessageType);
        Assert.Equal("10.66.66.66", rogue.Router);
        _det.OnDhcpServer(rogue);
        Assert.Contains(_events, e => e.Title == "Подозрительный DHCP-сервер" && e.Severity == NotificationSeverity.Critical && e.Message.Contains("10.66.66.66"));

        _events.Clear();
        Assert.True(LanFrameParser.TryParseDhcpServer(DhcpReply(5, "192.168.1.1"), "192.168.1.1", out var router));
        _det.OnDhcpServer(router);
        Assert.Empty(_events);
    }

    [Fact]
    public void LlmnrPoisoner_AnsweringManyNames_IsCritical()
    {
        byte[] Llmnr(string name)
        {
            var b = new List<byte> { 0x12, 0x34, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0 };
            b.Add((byte)name.Length); b.AddRange(Encoding.ASCII.GetBytes(name)); b.AddRange(new byte[] { 0, 0, 1, 0, 1 });
            return b.ToArray();
        }
        for (int i = 0; i < 6; i++)
        {
            Assert.True(LanFrameParser.TryParseNameResponse(5355, Llmnr("host" + i), "192.168.1.66", out var r));
            _det.OnNameResponse(r);
        }
        Assert.True(Has("Подмена имён (LLMNR)"));
    }

    [Fact]
    public void Nbns_ResponseName_Decoded()
    {
        var p = new List<byte> { 0x12, 0x34, 0x85, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x20 };
        foreach (var c in "FILESRV".PadRight(15))
        {
            p.Add((byte)('A' + (c >> 4))); p.Add((byte)('A' + (c & 0xF)));
        }
        p.Add((byte)'A'); p.Add((byte)'A'); p.Add(0);
        Assert.True(LanFrameParser.TryParseNameResponse(137, p.ToArray(), "192.168.1.5", out var r));
        Assert.Equal("FILESRV", r.Name);
        Assert.Equal("NBNS", r.Protocol);
    }
}
