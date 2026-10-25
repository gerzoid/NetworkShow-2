using System;
using System.Text;

namespace NetworkMonitor.Helpers;

public static class TlsSniExtractor
{
    /// <summary>Извлекает SNI из TLS-записи (record layer + ClientHello) — TCP-путь.</summary>
    public static string? TryExtract(byte[] payload) =>
        payload is null ? null : TryExtract((ReadOnlySpan<byte>)payload);

    public static string? TryExtract(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 43) return null;
        if (payload[0] != 0x16) return null;       // TLS record: Handshake
        return TryExtractFromHandshake(payload[5..]);
    }

    /// <summary>Извлекает SNI из handshake-сообщения ClientHello без record-слоя — QUIC-путь.</summary>
    public static string? TryExtractFromHandshake(byte[] data) =>
        data is null ? null : TryExtractFromHandshake((ReadOnlySpan<byte>)data);

    public static string? TryExtractFromHandshake(byte[] data, int start, int count)
    {
        if (data is null || start < 0 || count < 0 || start + count > data.Length) return null;
        return TryExtractFromHandshake(data.AsSpan(start, count));
    }

    public static string? TryExtractFromHandshake(ReadOnlySpan<byte> data)
    {
        if (data.Length < 38) return null;
        int end = data.Length;
        if (data[0] != 0x01) return null;           // Handshake type: ClientHello

        int pos = 4;                                // handshake header (type + 3-byte length)
        pos += 2;                                   // ClientVersion
        pos += 32;                                  // Random
        if (pos >= end) return null;

        int sessLen = data[pos++];
        pos += sessLen;
        if (pos + 2 > end) return null;

        int csLen = (data[pos] << 8) | data[pos + 1];
        pos += 2 + csLen;
        if (pos >= end) return null;

        int cmLen = data[pos++];
        pos += cmLen;
        if (pos + 2 > end) return null;

        int extLen = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        int extEnd = System.Math.Min(pos + extLen, end);

        while (pos + 4 <= extEnd)
        {
            int extType = (data[pos] << 8) | data[pos + 1];
            int extDataLen = (data[pos + 2] << 8) | data[pos + 3];
            pos += 4;
            if (pos + extDataLen > extEnd) return null;

            if (extType == 0x0000) // server_name
            {
                int p = pos;
                int snEnd = pos + extDataLen;
                if (p + 2 > snEnd) return null;
                p += 2; // skip ServerNameList length
                while (p + 3 <= snEnd)
                {
                    int nameType = data[p++];
                    int nameLen = (data[p] << 8) | data[p + 1];
                    p += 2;
                    if (p + nameLen > snEnd) return null;
                    if (nameType == 0x00) // host_name
                        return Encoding.ASCII.GetString(data.Slice(p, nameLen));
                    p += nameLen;
                }
            }
            pos += extDataLen;
        }
        return null;
    }
}
