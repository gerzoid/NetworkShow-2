using System.Security.Cryptography;
using System.Text;
using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class QuicSniExtractorTests
{
    private static readonly byte[] InitialSaltV1 =
        Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    [Fact]
    public void TryExtract_ValidInitialPacket_ReturnsSni()
    {
        var packet = BuildInitialPacket("www.example.com");
        Assert.Equal("www.example.com", QuicSniExtractor.TryExtract(packet));
    }

    [Fact]
    public void TryExtract_CyrillicPunycodeHost_ReturnsSni()
    {
        var packet = BuildInitialPacket("xn--80aswg.xn--p1ai");
        Assert.Equal("xn--80aswg.xn--p1ai", QuicSniExtractor.TryExtract(packet));
    }

    [Fact]
    public void TryExtract_TamperedCiphertext_ReturnsNull()
    {
        var packet = BuildInitialPacket("www.example.com");
        packet[^20] ^= 0xFF; // портим шифртекст — AES-GCM должен отвергнуть
        Assert.Null(QuicSniExtractor.TryExtract(packet));
    }

    [Fact]
    public void TryExtract_ShortHeader_ReturnsNull()
    {
        var packet = BuildInitialPacket("www.example.com");
        packet[0] = 0x40; // short header
        Assert.Null(QuicSniExtractor.TryExtract(packet));
    }

    [Fact]
    public void TryExtract_UnsupportedVersion_ReturnsNull()
    {
        var packet = BuildInitialPacket("www.example.com");
        packet[4] = 0x02; // QUIC v2 — другая соль, не поддерживаем
        Assert.Null(QuicSniExtractor.TryExtract(packet));
    }

    [Fact]
    public void TryExtract_TooShortDatagram_ReturnsNull()
    {
        Assert.Null(QuicSniExtractor.TryExtract(new byte[100]));
    }

    [Fact]
    public void TryExtract_RandomGarbage_DoesNotThrow()
    {
        var rng = new Random(7);
        for (int i = 0; i < 200; i++)
        {
            var garbage = new byte[1300];
            rng.NextBytes(garbage);
            garbage[0] = 0xC0;
            garbage[1] = 0x00; garbage[2] = 0x00; garbage[3] = 0x00; garbage[4] = 0x01;
            QuicSniExtractor.TryExtract(garbage); // важно только отсутствие исключений
        }
    }

    // --- Сборка настоящего Initial-пакета по RFC 9000/9001 ---

    private static byte[] BuildInitialPacket(string sni)
    {
        var clientHello = BuildClientHelloHandshake(sni);

        // CRYPTO-фрейм + PADDING до 1180 байт плейнтекста
        var frames = new List<byte> { 0x06 };
        frames.AddRange(EncodeVarint(0));
        frames.AddRange(EncodeVarint(clientHello.Length));
        frames.AddRange(clientHello);
        while (frames.Count < 1180) frames.Add(0x00);
        var plain = frames.ToArray();

        var dcid = new byte[] { 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 };
        const int pnLen = 1;

        var header = new List<byte>
        {
            0xC0,                   // long header, fixed bit, Initial, pn length 1
            0x00, 0x00, 0x00, 0x01, // version 1
            (byte)dcid.Length
        };
        header.AddRange(dcid);
        header.Add(0x00);           // SCID length
        header.Add(0x00);           // token length (varint 0)
        int length = pnLen + plain.Length + 16;
        header.Add((byte)(0x40 | (length >> 8))); // 2-байтовый varint
        header.Add((byte)(length & 0xFF));
        int pnOffset = header.Count;
        header.Add(0x00);           // packet number = 0
        var headerBytes = header.ToArray();

        var initialSecret = HKDF.Extract(HashAlgorithmName.SHA256, dcid, InitialSaltV1);
        var clientSecret = HkdfExpandLabel(initialSecret, "client in", 32);
        var key = HkdfExpandLabel(clientSecret, "quic key", 16);
        var iv = HkdfExpandLabel(clientSecret, "quic iv", 12);
        var hp = HkdfExpandLabel(clientSecret, "quic hp", 16);

        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(key, 16))
            gcm.Encrypt(iv, plain, cipher, tag, headerBytes); // pn=0 → nonce == iv

        var packet = new List<byte>(headerBytes);
        packet.AddRange(cipher);
        packet.AddRange(tag);
        var bytes = packet.ToArray();

        // Header protection (RFC 9001 §5.4)
        var sample = new byte[16];
        Array.Copy(bytes, pnOffset + 4, sample, 0, 16);
        var mask = new byte[16];
        using (var aes = Aes.Create())
        {
            aes.Key = hp;
            aes.EncryptEcb(sample, mask, PaddingMode.None);
        }
        bytes[0] ^= (byte)(mask[0] & 0x0F);
        bytes[pnOffset] ^= mask[1];
        return bytes;
    }

    private static byte[] BuildClientHelloHandshake(string sni)
    {
        var body = new List<byte> { 0x03, 0x03 }; // ClientVersion TLS 1.2
        body.AddRange(new byte[32]);              // Random
        body.Add(0x00);                           // SessionId length
        body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 }); // CipherSuites
        body.AddRange(new byte[] { 0x01, 0x00 });             // Compression

        var name = Encoding.ASCII.GetBytes(sni);
        var serverNameList = new List<byte>
        {
            (byte)((name.Length + 3) >> 8), (byte)((name.Length + 3) & 0xFF),
            0x00,
            (byte)(name.Length >> 8), (byte)(name.Length & 0xFF)
        };
        serverNameList.AddRange(name);

        var extensions = new List<byte> { 0x00, 0x00 }; // ExtensionType: server_name
        extensions.Add((byte)(serverNameList.Count >> 8));
        extensions.Add((byte)(serverNameList.Count & 0xFF));
        extensions.AddRange(serverNameList);

        body.Add((byte)(extensions.Count >> 8));
        body.Add((byte)(extensions.Count & 0xFF));
        body.AddRange(extensions);

        var handshake = new List<byte>
        {
            0x01, // ClientHello
            (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)(body.Count & 0xFF)
        };
        handshake.AddRange(body);
        return handshake.ToArray();
    }

    private static byte[] HkdfExpandLabel(byte[] secret, string label, int length)
    {
        var labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + labelBytes.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)labelBytes.Length;
        labelBytes.CopyTo(info, 3);
        var output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, secret, output, info);
        return output;
    }

    private static IEnumerable<byte> EncodeVarint(long value)
    {
        if (value < 64) return new[] { (byte)value };
        if (value < 16384) return new[] { (byte)(0x40 | (value >> 8)), (byte)(value & 0xFF) };
        throw new ArgumentOutOfRangeException(nameof(value));
    }
}
