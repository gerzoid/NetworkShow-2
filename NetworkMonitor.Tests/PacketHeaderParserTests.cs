using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using NetworkMonitor.Helpers;
using PacketDotNet;
using Xunit;

namespace NetworkMonitor.Tests;

public class PacketHeaderParserTests
{
    private const int LinkNull = 0, LinkEthernet = 1, LinkRaw = 101;

    private static readonly PhysicalAddress MacA = PhysicalAddress.Parse("00-11-22-33-44-55");
    private static readonly PhysicalAddress MacB = PhysicalAddress.Parse("66-77-88-99-AA-BB");

    private static byte[] EthernetFrame(IPPacket ip, EthernetType type)
    {
        var eth = new EthernetPacket(MacA, MacB, type) { PayloadPacket = ip };
        eth.UpdateCalculatedValues();
        return eth.Bytes;
    }

    private static IPv4Packet V4(string src, string dst, Packet transport)
    {
        var ip = new IPv4Packet(IPAddress.Parse(src), IPAddress.Parse(dst)) { PayloadPacket = transport };
        ip.UpdateCalculatedValues();
        return ip;
    }

    private static IPv6Packet V6(string src, string dst, Packet transport)
    {
        var ip = new IPv6Packet(IPAddress.Parse(src), IPAddress.Parse(dst)) { PayloadPacket = transport };
        ip.UpdateCalculatedValues();
        return ip;
    }

    private static IpKey Key(string ip)
    {
        var b = IPAddress.Parse(ip).GetAddressBytes();
        return b.Length == 4 ? IpKey.FromV4(b) : IpKey.FromV6(b);
    }

    [Fact]
    public void Ethernet_IPv4_Tcp_MatchesPacketDotNet()
    {
        var payload = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        var tcp = new TcpPacket(51234, 443) { PayloadData = payload };
        var frame = EthernetFrame(V4("192.168.1.10", "93.184.216.34", tcp), EthernetType.IPv4);

        Assert.True(PacketHeaderParser.TryParse(LinkEthernet, frame, out var h));
        Assert.True(h.IsTcp);
        Assert.Equal(Key("192.168.1.10"), h.Source);
        Assert.Equal(Key("93.184.216.34"), h.Destination);
        Assert.Equal(51234, h.SourcePort);
        Assert.Equal(443, h.DestinationPort);
        Assert.Equal(payload, frame.AsSpan(h.PayloadOffset, h.PayloadLength).ToArray());

        var reference = Packet.ParsePacket(LinkLayers.Ethernet, frame).Extract<TcpPacket>();
        Assert.Equal(reference.PayloadData, frame.AsSpan(h.PayloadOffset, h.PayloadLength).ToArray());
    }

    [Fact]
    public void Ethernet_IPv6_Udp()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var udp = new UdpPacket(5353, 53) { PayloadData = payload };
        udp.UpdateCalculatedValues();
        var frame = EthernetFrame(V6("2001:db8::1", "2001:db8::2", udp), EthernetType.IPv6);

        Assert.True(PacketHeaderParser.TryParse(LinkEthernet, frame, out var h));
        Assert.True(h.IsUdp);
        Assert.True(h.Source.IsV6);
        Assert.Equal(Key("2001:db8::1"), h.Source);
        Assert.Equal(Key("2001:db8::2"), h.Destination);
        Assert.Equal(5353, h.SourcePort);
        Assert.Equal(53, h.DestinationPort);
        Assert.Equal(payload, frame.AsSpan(h.PayloadOffset, h.PayloadLength).ToArray());
    }

    [Fact]
    public void Ethernet_TrailingPadding_IsExcludedFromPayload()
    {
        var udp = new UdpPacket(1000, 2000) { PayloadData = new byte[] { 0xAB } };
        udp.UpdateCalculatedValues();
        var frame = EthernetFrame(V4("10.0.0.1", "10.0.0.2", udp), EthernetType.IPv4)
            .Concat(new byte[17]).ToArray(); // дополнение Ethernet до 60 байт

        Assert.True(PacketHeaderParser.TryParse(LinkEthernet, frame, out var h));
        Assert.Equal(1, h.PayloadLength);
        Assert.Equal(0xAB, frame[h.PayloadOffset]);
    }

    [Fact]
    public void Vlan_Tagged_IPv4()
    {
        var tcp = new TcpPacket(80, 40000);
        var plain = EthernetFrame(V4("10.0.0.1", "10.0.0.2", tcp), EthernetType.IPv4);
        // Вставляем 802.1Q-тег после MAC-адресов
        var frame = plain[..12].Concat(new byte[] { 0x81, 0x00, 0x00, 0x05 }).Concat(plain[12..]).ToArray();

        Assert.True(PacketHeaderParser.TryParse(LinkEthernet, frame, out var h));
        Assert.True(h.IsTcp);
        Assert.Equal(80, h.SourcePort);
        Assert.Equal(40000, h.DestinationPort);
    }

    [Fact]
    public void NullLink_And_RawLink()
    {
        var udp = new UdpPacket(1, 2);
        udp.UpdateCalculatedValues();
        var ip = V4("127.0.0.1", "127.0.0.1", udp).Bytes;

        var loopback = new byte[] { 2, 0, 0, 0 }.Concat(ip).ToArray(); // AF_INET, host order
        Assert.True(PacketHeaderParser.TryParse(LinkNull, loopback, out var h1));
        Assert.Equal(2, h1.DestinationPort);

        Assert.True(PacketHeaderParser.TryParse(LinkRaw, ip, out var h2));
        Assert.Equal(1, h2.SourcePort);
    }

    [Fact]
    public void IPv4_LaterFragment_HasNoPorts()
    {
        var udp = new UdpPacket(1234, 5678);
        udp.UpdateCalculatedValues();
        var frame = EthernetFrame(V4("10.0.0.1", "10.0.0.2", udp), EthernetType.IPv4);
        frame[14 + 6] = 0x00;
        frame[14 + 7] = 0xB9; // fragment offset != 0

        Assert.True(PacketHeaderParser.TryParse(LinkEthernet, frame, out var h));
        Assert.True(h.IsUdp);
        Assert.Equal(0, h.SourcePort);
        Assert.Equal(0, h.PayloadLength);
    }

    [Fact]
    public void IPv4_ZeroTotalLength_UsesFrameLength()
    {
        // Large Send Offload: Npcap отдаёт Total Length = 0
        var tcp = new TcpPacket(1, 2) { PayloadData = new byte[50] };
        var frame = EthernetFrame(V4("10.0.0.1", "10.0.0.2", tcp), EthernetType.IPv4);
        frame[14 + 2] = 0;
        frame[14 + 3] = 0;

        Assert.True(PacketHeaderParser.TryParse(LinkEthernet, frame, out var h));
        Assert.Equal(50, h.PayloadLength);
    }

    [Fact]
    public void IPv6_HopByHopExtension_IsSkipped()
    {
        var udp = new UdpPacket(546, 547) { PayloadData = new byte[] { 9 } };
        udp.UpdateCalculatedValues();
        var ip = V6("fe80::1", "ff02::1:2", udp).Bytes;

        // Вставляем 8-байтовый Hop-by-Hop между заголовком IPv6 и UDP
        var hbh = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 };
        var withExt = ip[..40].Concat(hbh).Concat(ip[40..]).ToArray();
        withExt[6] = 0;                                       // Next Header = Hop-by-Hop
        int payloadLen = withExt.Length - 40;
        withExt[4] = (byte)(payloadLen >> 8);
        withExt[5] = (byte)payloadLen;

        Assert.True(PacketHeaderParser.TryParse(LinkRaw, withExt, out var h));
        Assert.True(h.IsUdp);
        Assert.Equal(546, h.SourcePort);
        Assert.Equal(547, h.DestinationPort);
        Assert.Equal(1, h.PayloadLength);
    }

    [Fact]
    public void Arp_IsNotIp()
    {
        var frame = new byte[42];
        frame[12] = 0x08;
        frame[13] = 0x06;
        Assert.False(PacketHeaderParser.TryParse(LinkEthernet, frame, out _));
    }

    [Fact]
    public void TruncatedTcpHeader_ReturnsFalse()
    {
        var tcp = new TcpPacket(1, 2);
        var frame = EthernetFrame(V4("10.0.0.1", "10.0.0.2", tcp), EthernetType.IPv4);
        var truncated = frame[..(14 + 20 + 10)];
        truncated[14 + 2] = 0;
        truncated[14 + 3] = 0;

        Assert.False(PacketHeaderParser.TryParse(LinkEthernet, truncated, out _));
    }

    [Fact]
    public void GarbageInput_DoesNotThrow()
    {
        var rnd = new Random(42);
        for (int i = 0; i < 10_000; i++)
        {
            var buf = new byte[rnd.Next(0, 120)];
            rnd.NextBytes(buf);
            if (buf.Length > 14) { buf[12] = 0x08; buf[13] = 0x00; buf[14] = (byte)(0x40 | (buf[14] & 0x0F)); }
            PacketHeaderParser.TryParse(LinkEthernet, buf, out _);
            PacketHeaderParser.TryParse(LinkRaw, buf, out _);
        }
    }

    [Fact]
    public void TlsSni_FromSpan_EqualsArray()
    {
        // Минимальный ClientHello с SNI "example.com"
        var host = "example.com"u8.ToArray();
        var sniExt = new byte[] { 0x00, 0x00, 0, (byte)(host.Length + 5), 0, (byte)(host.Length + 3), 0x00, 0, (byte)host.Length }
            .Concat(host).ToArray();
        var body = new byte[] { 0x03, 0x03 }.Concat(new byte[32]).Concat(new byte[] { 0, 0, 2, 0x13, 0x01, 1, 0 })
            .Concat(new byte[] { 0, (byte)sniExt.Length }).Concat(sniExt).ToArray();
        var hs = new byte[] { 0x01, 0, 0, (byte)body.Length }.Concat(body).ToArray();
        var record = new byte[] { 0x16, 0x03, 0x01, 0, (byte)hs.Length }.Concat(hs).ToArray();

        Assert.Equal("example.com", TlsSniExtractor.TryExtract(record));
        Assert.Equal("example.com", TlsSniExtractor.TryExtract((ReadOnlySpan<byte>)record));
    }
}
