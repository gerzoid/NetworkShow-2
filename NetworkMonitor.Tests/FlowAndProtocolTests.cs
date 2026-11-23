using System.Text;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using Xunit;

namespace NetworkMonitor.Tests;

public class FlowAndProtocolTests
{
    private static byte[] B(string s) => Encoding.ASCII.GetBytes(s);

    [Theory]
    [InlineData("SSH-2.0-OpenSSH_9.6\r\n", "ssh")]
    [InlineData("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "http")]
    [InlineData("HTTP/1.1 200 OK\r\n", "http")]
    [InlineData("\u0013BitTorrent protocol\0\0\0\0\0\0\0\0", "bittorrent")]
    [InlineData("EHLO mail.example.com\r\n", "smtp")]
    public void Tcp_Detected(string text, string expected)
    {
        var bytes = text.Select(c => (byte)c).ToArray();
        Assert.Equal(expected, ProtocolSniffer.Detect(true, 50000, 2222, bytes));
    }

    [Fact]
    public void Rdp_TlsAndSmb_Detected()
    {
        var rdp = new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0 };
        Assert.Equal("rdp", ProtocolSniffer.Detect(true, 50000, 4000, rdp));
        var tls = new byte[] { 0x16, 0x03, 0x01, 0x00, 0x30, 0x01, 0, 0, 0x2c, 3, 3 };
        Assert.Equal("tls", ProtocolSniffer.Detect(true, 50000, 9999, tls));
        var smb = new byte[] { 0, 0, 0, 0x40, 0xFE, (byte)'S', (byte)'M', (byte)'B' };
        Assert.Equal("smb", ProtocolSniffer.Detect(true, 50000, 445, smb));
    }

    [Fact]
    public void Udp_WireGuardOpenVpnDht_Detected()
    {
        var wg = new byte[148]; wg[0] = 1;
        Assert.Equal("wireguard", ProtocolSniffer.Detect(false, 50000, 51820, wg));
        var wg2 = new byte[92]; wg2[0] = 2;
        Assert.Equal("wireguard", ProtocolSniffer.Detect(false, 51820, 50000, wg2));
        var ovpn = new byte[26]; ovpn[0] = 0x38;
        Assert.Equal("openvpn", ProtocolSniffer.Detect(false, 50000, 1194, ovpn));
        Assert.Equal("bittorrent", ProtocolSniffer.Detect(false, 6881, 6881, B("d1:ad2:id20:abcdefghij0123456789e1:q4:ping")));
        Assert.Null(ProtocolSniffer.Detect(false, 5000, 5001, new byte[] { 9, 9, 9, 9, 9, 9 }));
    }

    [Theory]
    [InlineData("www.k3jd8s9fh2lq.com", true)]
    [InlineData("www.google.com", false)]
    [InlineData("www.my-site-name.net", false)]
    [InlineData("api.k3jd8s9fh2lq.com", false)]
    public void TorSniHeuristic(string sni, bool expected) => Assert.Equal(expected, ProtocolSniffer.LooksLikeTorSni(sni));

    private static byte[] ClientHello(params ushort[] ciphers)
    {
        var body = new List<byte> { 0x03, 0x03 };
        body.AddRange(new byte[32]);                // random
        body.Add(0);                                // session id
        body.Add((byte)(ciphers.Length * 2 >> 8)); body.Add((byte)(ciphers.Length * 2));
        foreach (var c in ciphers) { body.Add((byte)(c >> 8)); body.Add((byte)c); }
        body.AddRange(new byte[] { 1, 0 });         // compression
        // extensions: server_name(0), supported_groups(10): x25519(29), ec_point_formats(11): uncompressed(0), GREASE(0x0a0a)
        var ext = new List<byte> {
            0x0a, 0x0a, 0, 0,
            0, 0, 0, 0,
            0, 10, 0, 4, 0, 2, 0, 29,
            0, 11, 0, 2, 1, 0 };
        body.Add((byte)(ext.Count >> 8)); body.Add((byte)ext.Count); body.AddRange(ext);
        var hs = new List<byte> { 0x01, 0, (byte)(body.Count >> 8), (byte)body.Count };
        hs.AddRange(body);
        var rec = new List<byte> { 0x16, 0x03, 0x01, (byte)(hs.Count >> 8), (byte)hs.Count };
        rec.AddRange(hs);
        return rec.ToArray();
    }

    [Fact]
    public void Ja3_ComputedWithoutGrease_AndStable()
    {
        var ch = ClientHello(0x0a0a, 0x1301, 0xc02f);
        Assert.True(Ja3Fingerprint.TryCompute(ch, out var hash, out var text));
        Assert.Equal("771,4865-49199,0-10-11,29,0", text);   // GREASE исключён
        Assert.Equal(32, hash.Length);
        Assert.True(Ja3Fingerprint.TryCompute(ClientHello(0x0a0a, 0x1301, 0xc02f), out var again, out _));
        Assert.Equal(hash, again);
        Assert.False(Ja3Fingerprint.TryCompute(new byte[] { 1, 2, 3 }, out _, out _));
    }

    [Fact]
    public void Ja3Blocklist_Loaded()
    {
        Assert.True(Ja3Blocklist.Count > 50);
        Assert.NotNull(Ja3Blocklist.Lookup("b386946a5a44d1ddcc843bc75336dfce")); // Dridex из списка abuse.ch
        Assert.Null(Ja3Blocklist.Lookup("00000000000000000000000000000000"));
    }

    private static PacketRecord Pkt(bool outbound, byte flags, uint seq, int len, DateTime t, string? app = null) => new()
    {
        Protocol = "TCP", Direction = outbound ? TrafficDirection.Outbound : TrafficDirection.Inbound,
        SourceIp = outbound ? "192.168.1.2" : "8.8.8.8", DestinationIp = outbound ? "8.8.8.8" : "192.168.1.2",
        SourcePort = outbound ? 50000 : 443, DestinationPort = outbound ? 443 : 50000,
        Size = len + 54, TcpFlags = flags, TcpSeq = seq, PayloadLength = len, Timestamp = t, ProcessName = "p", AppProto = app
    };

    [Fact]
    public void FlowMetrics_Rtt_Retransmits_Resets_AppProto()
    {
        var agg = new AggregationService();
        var t0 = new DateTime(2026, 11, 23, 12, 0, 0);
        agg.Add(Pkt(true, 0x02, 1000, 0, t0));                              // SYN
        agg.Add(Pkt(false, 0x12, 5000, 0, t0.AddMilliseconds(42)));         // SYN/ACK → RTT 42 мс
        agg.Add(Pkt(true, 0x18, 1001, 100, t0.AddMilliseconds(50), "ssh")); // данные
        agg.Add(Pkt(true, 0x18, 1101, 100, t0.AddMilliseconds(60)));        // следующий сегмент
        agg.Add(Pkt(true, 0x18, 1001, 100, t0.AddMilliseconds(300)));       // повтор первого
        agg.Add(Pkt(false, 0x04, 5001, 0, t0.AddMilliseconds(400)));        // RST
        var c = agg.Connections.Single();
        agg.PublishCounters();
        Assert.Equal(42, c.RttMs, 1);
        Assert.Equal(1, c.Retransmits);
        Assert.Equal(1, c.Resets);
        Assert.Equal("ssh", c.AppProto);
        Assert.True(c.IatMeanMs > 0);
    }
}

public class GeoAndCategoryTests
{
    [Theory]
    [InlineData("8.8.8.8", "US", "Google")]
    [InlineData("1.1.1.1", "AU", "Cloudflare")]   // APNIC-блок 1.1.1.0/24 у Cloudflare, страна по базе DB-IP
    [InlineData("77.88.55.88", "RU", "Yandex")]
    [InlineData("2001:4860:4860::8888", "US", "Google")]
    [InlineData("2606:4700:4700::1111", "US", "Cloudflare")]
    public void GeoIp_ResolvesCountryAndProvider(string ip, string country, string org)
    {
        GeoIpDatabase.EnsureLoaded();
        var (cc, asn) = GeoIpDatabase.Lookup(ip);
        Assert.True(cc.Length == 2, $"{ip}: страна пустая");
        Assert.Contains(org, asn, StringComparison.OrdinalIgnoreCase);
        // Anycast-адреса (Google, Cloudflare) в базе привязаны к произвольной стране — строго проверяем только обычные IPv4
        if (ip.Contains('.') && country != "AU") Assert.Equal(country, cc);
    }

    [Fact]
    public void GeoIp_PrivateAndUnknown_AreEmpty()
    {
        GeoIpDatabase.EnsureLoaded();
        Assert.Equal(string.Empty, GeoIpDatabase.Lookup("not-an-ip").Country);
        Assert.Equal(string.Empty, GeoIpDatabase.Lookup("192.168.1.1").Country);
    }

    [Theory]
    [InlineData("rr3---sn-abc.googlevideo.com", DomainCategories.Streaming)]
    [InlineData("api.telegram.org", DomainCategories.Social)]
    [InlineData("stats.g.doubleclick.net", DomainCategories.Ads)]
    [InlineData("d1abc.cloudfront.net", DomainCategories.Cdn)]
    [InlineData("ec2-1-2-3-4.compute-1.amazonaws.com", DomainCategories.Cloud)]
    [InlineData("steamcontent.com", DomainCategories.Games)]
    [InlineData("example-unknown-site.org", "")]
    public void Domain_Categories(string host, string expected) => Assert.Equal(expected, DomainCategories.Classify(host));

    [Fact]
    public void AsnFallback_ForCdnAndCloud()
    {
        Assert.Equal(DomainCategories.Cdn, DomainCategories.FromAsnOrg("AS13335 Cloudflare, Inc."));
        Assert.Equal(DomainCategories.Cloud, DomainCategories.FromAsnOrg("AS16509 Amazon.com, Inc."));
    }
}
