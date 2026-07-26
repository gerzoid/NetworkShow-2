using System.Text;
using NetworkMonitor.Helpers;
using Xunit;

namespace NetworkMonitor.Tests;

public class TlsSniExtractorTests
{
    /// <summary>Собирает минимальный корректный TLS ClientHello с расширением server_name.</summary>
    private static byte[] BuildClientHello(string? sni, byte recordType = 0x16, byte handshakeType = 0x01)
    {
        var body = new List<byte>
        {
            0x03, 0x03 // ClientVersion TLS 1.2
        };
        body.AddRange(new byte[32]);          // Random
        body.Add(0x00);                       // SessionId length
        body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 }); // CipherSuites: len 2, TLS_AES_128_GCM_SHA256
        body.AddRange(new byte[] { 0x01, 0x00 });             // Compression: len 1, null

        var extensions = new List<byte>();
        if (sni is not null)
        {
            var name = Encoding.ASCII.GetBytes(sni);
            var serverNameList = new List<byte>
            {
                (byte)((name.Length + 3) >> 8), (byte)((name.Length + 3) & 0xFF), // ServerNameList length
                0x00,                                                             // NameType: host_name
                (byte)(name.Length >> 8), (byte)(name.Length & 0xFF)
            };
            serverNameList.AddRange(name);

            extensions.Add(0x00); extensions.Add(0x00); // ExtensionType: server_name
            extensions.Add((byte)(serverNameList.Count >> 8));
            extensions.Add((byte)(serverNameList.Count & 0xFF));
            extensions.AddRange(serverNameList);
        }

        body.Add((byte)(extensions.Count >> 8));
        body.Add((byte)(extensions.Count & 0xFF));
        body.AddRange(extensions);

        var handshake = new List<byte>
        {
            handshakeType,
            (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)(body.Count & 0xFF)
        };
        handshake.AddRange(body);

        var record = new List<byte>
        {
            recordType, 0x03, 0x01,
            (byte)(handshake.Count >> 8), (byte)(handshake.Count & 0xFF)
        };
        record.AddRange(handshake);
        return record.ToArray();
    }

    [Fact]
    public void TryExtract_ValidClientHello_ReturnsSni()
    {
        var payload = BuildClientHello("example.com");
        Assert.Equal("example.com", TlsSniExtractor.TryExtract(payload));
    }

    [Fact]
    public void TryExtract_LongHostname_ReturnsSni()
    {
        var host = new string('a', 200) + ".example.com";
        var payload = BuildClientHello(host);
        Assert.Equal(host, TlsSniExtractor.TryExtract(payload));
    }

    [Fact]
    public void TryExtract_NoSniExtension_ReturnsNull()
    {
        var payload = BuildClientHello(null);
        Assert.Null(TlsSniExtractor.TryExtract(payload));
    }

    [Fact]
    public void TryExtract_NotHandshakeRecord_ReturnsNull()
    {
        var payload = BuildClientHello("example.com", recordType: 0x17);
        Assert.Null(TlsSniExtractor.TryExtract(payload));
    }

    [Fact]
    public void TryExtract_NotClientHello_ReturnsNull()
    {
        var payload = BuildClientHello("example.com", handshakeType: 0x02);
        Assert.Null(TlsSniExtractor.TryExtract(payload));
    }

    [Fact]
    public void TryExtract_TruncatedPayload_ReturnsNullWithoutThrowing()
    {
        var full = BuildClientHello("example.com");
        for (int len = 0; len < full.Length; len++)
        {
            var truncated = full.Take(len).ToArray();
            // Не должен ни бросить, ни вернуть мусор — только null
            Assert.Null(TlsSniExtractor.TryExtract(truncated));
        }
    }

    [Fact]
    public void TryExtract_RandomGarbage_DoesNotThrow()
    {
        var rng = new Random(42);
        for (int i = 0; i < 500; i++)
        {
            var garbage = new byte[rng.Next(0, 300)];
            rng.NextBytes(garbage);
            if (garbage.Length > 0) garbage[0] = 0x16;
            if (garbage.Length > 5) garbage[5] = 0x01;
            TlsSniExtractor.TryExtract(garbage); // важно только отсутствие исключений
        }
    }
}
