using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

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
}
