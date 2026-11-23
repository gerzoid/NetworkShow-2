using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

[Collection("Settings")]
public class AnomalyDetectionServiceTests : IDisposable
{
    private const byte Syn = 0x02;
    private long _now = 1_000_000;
    private readonly NotificationService _notify = new();
    private readonly AnomalyDetectionService _svc;
    private readonly List<TrafficNotification> _events = new();

    public AnomalyDetectionServiceTests()
    {
        SettingsService.Persist = false;
        SettingsService.Current.Detection = new DetectionSettings();
        SettingsService.Current.KnownProcesses = new List<string> { "seed" }; // без «обучения»
        _notify.NotificationRaised += (_, n) => _events.Add(n);
        _svc = new AnomalyDetectionService(_notify) { Clock = () => _now };
        _svc.Start();
    }

    public void Dispose() => _svc.Dispose();

    private static PacketRecord Pkt(string src, int sport, string dst, int dport, TrafficDirection dir,
        string proc = "app", int size = 100, byte flags = 0, string proto = "TCP") => new()
    {
        SourceIp = src, SourcePort = sport, DestinationIp = dst, DestinationPort = dport,
        Direction = dir, ProcessName = proc, Size = size, TcpFlags = flags, Protocol = proto
    };

    private bool Has(string title) => _events.Any(e => e.Title == title);

    [Fact]
    public void PortScan_FromExternalIp_RaisesCritical()
    {
        for (int p = 1000; p < 1020; p++)
            _svc.Inspect(Pkt("8.8.8.8", 5555, "192.168.1.10", p, TrafficDirection.Inbound, flags: Syn));
        Assert.Contains(_events, e => e.Title == "Сканирование портов" && e.Severity == NotificationSeverity.Critical);
    }

    [Fact]
    public void FewPorts_NoScanAlert()
    {
        for (int p = 1000; p < 1005; p++)
            _svc.Inspect(Pkt("8.8.8.8", 5555, "192.168.1.10", p, TrafficDirection.Inbound, flags: Syn));
        Assert.False(Has("Сканирование портов"));
    }

    [Fact]
    public void WhitelistedIp_IsIgnored()
    {
        _notify.AddToWhitelist("8.8.8.8");
        for (int p = 1000; p < 1030; p++)
            _svc.Inspect(Pkt("8.8.8.8", 5555, "192.168.1.10", p, TrafficDirection.Inbound, flags: Syn));
        Assert.Empty(_events);
    }

    [Fact]
    public void InboundRdp_FromExternal_RaisesExposure()
    {
        _svc.Inspect(Pkt("1.2.3.4", 4000, "192.168.1.10", 3389, TrafficDirection.Inbound, flags: Syn));
        Assert.Contains(_events, e => e.Title == "Входящее подключение извне" && e.Severity == NotificationSeverity.Critical);
    }

    [Fact]
    public void InboundRdp_FromLan_NoExposureAlert()
    {
        _svc.Inspect(Pkt("192.168.1.50", 4000, "192.168.1.10", 3389, TrafficDirection.Inbound, flags: Syn));
        Assert.False(Has("Входящее подключение извне"));
    }

    [Fact]
    public void BruteForce_ManyConnectionsToRdp()
    {
        for (int i = 0; i < 25; i++)
            _svc.Inspect(Pkt("1.2.3.4", 4000 + i, "192.168.1.10", 3389, TrafficDirection.Inbound, flags: Syn));
        Assert.True(Has("Подозрение на подбор пароля"));
    }

    [Fact]
    public void Beaconing_RegularIntervals_Detected()
    {
        for (int i = 0; i < 12; i++)
        {
            _now += 30_000;
            _svc.Inspect(Pkt("192.168.1.10", 6000 + i, "5.6.7.8", 443, TrafficDirection.Outbound, "implant", flags: Syn));
        }
        Assert.True(Has("Периодические подключения (beaconing)"));
    }

    [Fact]
    public void Beaconing_IrregularIntervals_NotDetected()
    {
        var gaps = new[] { 5, 40, 12, 90, 7, 33, 61, 9, 50, 22, 80, 15 };
        foreach (var g in gaps)
        {
            _now += g * 1000L;
            _svc.Inspect(Pkt("192.168.1.10", 6000, "5.6.7.8", 443, TrafficDirection.Outbound, "browser", flags: Syn));
        }
        Assert.False(Has("Периодические подключения (beaconing)"));
    }

    [Fact]
    public void OutboundBurst_AfterBaseline_RaisesSpike()
    {
        // 70 корзин по 5 с с маленьким фоновым трафиком
        for (int i = 0; i < 70; i++)
        {
            _now += 5_000;
            _svc.Inspect(Pkt("192.168.1.10", 7000, "5.6.7.8", 443, TrafficDirection.Outbound, "uploader", size: 1000));
        }
        _now += 5_000;
        _svc.Inspect(Pkt("192.168.1.10", 7000, "5.6.7.8", 443, TrafficDirection.Outbound, "uploader", size: 50_000_000));
        _now += 5_000; // закрыть корзину со всплеском
        _svc.Inspect(Pkt("192.168.1.10", 7000, "5.6.7.8", 443, TrafficDirection.Outbound, "uploader", size: 1000));
        Assert.True(Has("Всплеск исходящего трафика"));
    }

    [Fact]
    public void Lolbin_GoingExternal_Warns_AndNewProcessReported()
    {
        _svc.Inspect(Pkt("192.168.1.10", 7000, "5.6.7.8", 443, TrafficDirection.Outbound, "powershell"));
        Assert.True(Has("Системная утилита выходит в сеть"));
        Assert.True(Has("Новый процесс в сети"));
    }

    [Fact]
    public void LocalOutbound_IsIgnored()
    {
        _svc.Inspect(Pkt("192.168.1.10", 7000, "192.168.1.20", 445, TrafficDirection.Outbound, "powershell"));
        Assert.Empty(_events);
    }

    private static PacketRecord Dns(string name, string proc = "malware") => new()
    {
        Protocol = "UDP", Direction = TrafficDirection.Outbound, SourceIp = "192.168.1.10", DestinationIp = "192.168.1.1",
        DestinationPort = 53, ProcessName = proc, DnsName = name
    };

    [Fact]
    public void Dga_ManyRandomDomains_Warns()
    {
        string[] names = { "xk3j9qz7vw2plm8r.com", "q8w7e6r5t4y3u2i1o0.net", "zx9cv8bn7m6lk5jh4g.org",
                           "p0o9i8u7y6t5r4e3w2q1.com", "m1n2b3v4c5x6z7a8s9d0.info", "l9k8j7h6g5f4d3s2a1.biz" };
        foreach (var n in names) _svc.Inspect(Dns(n));
        Assert.True(Has("Возможный DGA (случайные домены)"));
    }

    [Fact]
    public void Dga_NormalDomains_NoAlert()
    {
        foreach (var n in new[] { "www.google.com", "github.com", "update.microsoft.com", "cdn.example.org", "mail.yandex.ru", "login.live.com" })
            _svc.Inspect(Dns(n, "browser"));
        Assert.False(Has("Возможный DGA (случайные домены)"));
    }

    [Fact]
    public void DnsTunnel_ManyUniqueSubdomains_Warns()
    {
        for (int i = 0; i < 60; i++) _svc.Inspect(Dns($"chunk{i}abc.t.evil.com", "dnscat"));
        Assert.True(Has("Подозрение на DNS-туннель"));
    }

    [Fact]
    public void Dot_FromNonBrowser_Warns_ButBrowserIgnored()
    {
        _svc.Inspect(Pkt("192.168.1.10", 7000, "9.9.9.9", 853, TrafficDirection.Outbound, "chrome", flags: Syn));
        Assert.False(Has("Шифрованный DNS в обход системы"));
        _svc.Inspect(Pkt("192.168.1.10", 7001, "9.9.9.9", 853, TrafficDirection.Outbound, "updater", flags: Syn));
        Assert.True(Has("Шифрованный DNS в обход системы"));
    }

    [Fact]
    public void Doh_BySni_FromNonBrowser_Warns()
    {
        var p = Pkt("192.168.1.10", 7002, "8.8.8.8", 443, TrafficDirection.Outbound, "agent");
        var withSni = new PacketRecord
        {
            SourceIp = p.SourceIp, DestinationIp = p.DestinationIp, DestinationPort = 443, Protocol = "TCP",
            Direction = TrafficDirection.Outbound, ProcessName = "agent", Sni = "dns.google"
        };
        _svc.Inspect(withSni);
        Assert.True(Has("Шифрованный DNS в обход системы"));
    }

    [Fact]
    public void InspectDnsQuery_FromEtw_FeedsDetector()
    {
        for (int i = 0; i < 60; i++) _svc.InspectDnsQuery($"chunk{i}abc.t.evil.com", "dnscat");
        Assert.True(Has("Подозрение на DNS-туннель"));
    }

    [Fact]
    public void ReverseDnsLookups_AreNotTunnel()
    {
        for (int i = 0; i < 80; i++) _svc.InspectDnsQuery($"{i}.1.168.192.in-addr.arpa", "NetworkMonitor");
        Assert.False(Has("Подозрение на DNS-туннель"));
    }

    [Fact]
    public void ExternalNetbiosUdp_Warns_LanIgnored()
    {
        _svc.Inspect(Pkt("192.168.1.50", 137, "192.168.1.10", 137, TrafficDirection.Inbound, proto: "UDP"));
        Assert.False(Has("Входящий NetBIOS из внешней сети"));
        _svc.Inspect(Pkt("1.2.3.4", 137, "192.168.1.10", 137, TrafficDirection.Inbound, proto: "UDP"));
        Assert.True(Has("Входящий NetBIOS из внешней сети"));
    }

    [Fact]
    public void Netbios139_Bruteforce_Counted()
    {
        for (int i = 0; i < 25; i++)
            _svc.Inspect(Pkt("1.2.3.4", 4000 + i, "192.168.1.10", 139, TrafficDirection.Inbound, flags: Syn));
        Assert.True(Has("Подозрение на подбор пароля"));
    }

    private static NetworkMonitor.Helpers.TcpTableReader.Row Listen(string addr, int port, int pid) =>
        new(System.Net.IPAddress.Parse(addr), port, System.Net.IPAddress.Any, 0, pid);

    [Fact]
    public void NewListeningPort_NamesTheOwningProcess()
    {
        var listeners = new List<(System.Net.IPAddress, int)> { (System.Net.IPAddress.Any, 445) };
        _svc.ListenerSource = () => listeners.ToList();
        _svc.TcpRows = () => new() { Listen("0.0.0.0", 445, 4), Listen("0.0.0.0", 5555, 4242) };
        _svc.ProcessInfo = pid => pid == 4242 ? ("adb", @"C:\tools\platform-tools\adb.exe") : (null, null);

        _svc.CheckListeners();                 // первый снимок — база без тревог
        Assert.Empty(_events);

        listeners.Add((System.Net.IPAddress.Any, 5555));
        _svc.CheckListeners();
        var n = Assert.Single(_events, e => e.Title == "Новый слушающий порт");
        Assert.Contains("adb (PID 4242)", n.Message);
        Assert.Contains(@"C:\tools\platform-tools\adb.exe", n.Message);
        Assert.Contains("0.0.0.0:5555", n.Message);
    }

    [Fact]
    public void NewListeningPort_OwnerGone_SaysSo()
    {
        var listeners = new List<(System.Net.IPAddress, int)>();
        _svc.ListenerSource = () => listeners.ToList();
        _svc.TcpRows = () => new();
        _svc.CheckListeners();
        listeners.Add((System.Net.IPAddress.Any, 6000));
        _svc.CheckListeners();
        var n = Assert.Single(_events, e => e.Title == "Новый слушающий порт");
        Assert.Contains("владельца определить не удалось", n.Message);
    }

    [Fact]
    public void SystemPid4_IsExplained()
    {
        var listeners = new List<(System.Net.IPAddress, int)>();
        _svc.ListenerSource = () => listeners.ToList();
        _svc.TcpRows = () => new() { Listen("0.0.0.0", 8080, 4) };
        _svc.CheckListeners();
        listeners.Add((System.Net.IPAddress.Any, 8080));
        _svc.CheckListeners();
        Assert.Contains(_events, e => e.Message.Contains("PID 4"));
    }

    private static PacketRecord App(string proto, int dport, string proc = "tool", string? sni = null, string? ja3 = null, string dst = "5.6.7.8", TrafficDirection dir = TrafficDirection.Outbound) => new()
    {
        Protocol = proto is "wireguard" or "openvpn" or "bittorrent" && dport != 80 ? "UDP" : "TCP",
        Direction = dir, SourceIp = dir == TrafficDirection.Outbound ? "192.168.1.10" : dst, DestinationIp = dir == TrafficDirection.Outbound ? dst : "192.168.1.10",
        SourcePort = dir == TrafficDirection.Outbound ? 50000 : dport, DestinationPort = dir == TrafficDirection.Outbound ? dport : 50000,
        ProcessName = proc, AppProto = proto, Sni = sni, Ja3 = ja3
    };

    [Fact]
    public void SshOnOddPort_Info_ButNotOnPort22()
    {
        _svc.Inspect(App("ssh", 22));
        Assert.False(Has("SSH на нестандартном порту"));
        _svc.Inspect(App("ssh", 2222));
        Assert.Contains(_events, e => e.Title == "SSH на нестандартном порту" && e.Severity == NotificationSeverity.Info);
    }

    [Fact]
    public void RdpOnOddPort_Warns_BitTorrentAndVpn_AreInfo()
    {
        _svc.Inspect(App("rdp", 8443));
        Assert.Contains(_events, e => e.Title == "RDP на нестандартном порту" && e.Severity == NotificationSeverity.Warning);
        _svc.Inspect(App("bittorrent", 6881, "qbittorrent"));
        Assert.True(Has("Обнаружен трафик BitTorrent"));
        _svc.Inspect(App("wireguard", 51820));
        Assert.True(Has("VPN-протокол"));
    }

    [Fact]
    public void Tor_Telnet_SmbToInternet_AreWarnings()
    {
        _svc.Inspect(App("tls", 9001, "tor", sni: "www.k3jd8s9fh2lq.com"));
        Assert.True(Has("Похоже на трафик Tor"));
        _svc.Inspect(App("telnet", 23));
        Assert.True(Has("Telnet: данные открытым текстом"));
        _svc.Inspect(App("smb", 445));
        Assert.True(Has("SMB в интернет"));
        _events.Clear();
        _svc.Inspect(App("smb", 445, dst: "192.168.1.50"));
        Assert.False(Has("SMB в интернет"));
    }

    [Fact]
    public void KnownBadJa3_Warns()
    {
        _svc.Inspect(App("tls", 443, ja3: "b386946a5a44d1ddcc843bc75336dfce"));
        Assert.Contains(_events, e => e.Title.StartsWith("TLS-отпечаток") && e.Message.Contains("Dridex"));
        _events.Clear();
        _svc.Inspect(App("tls", 443, ja3: "00000000000000000000000000000000"));
        Assert.Empty(_events);
    }
}
