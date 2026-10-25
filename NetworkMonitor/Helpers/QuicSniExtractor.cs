using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Извлекает TLS SNI из QUIC v1 Initial-пакета (HTTP/3, UDP/443).
/// Initial-пакеты защищены ключами, выводимыми из Destination Connection ID
/// по фиксированной соли (RFC 9001 §5.2), поэтому расшифровываются пассивно.
/// </summary>
public static class QuicSniExtractor
{
    // RFC 9001 §5.2, соль для QUIC v1
    private static readonly byte[] InitialSaltV1 =
        Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    public static string? TryExtract(byte[] payload)
    {
        // Криптография и парсинг недоверенных данных: любая ошибка
        // (битый пакет, не тот ключ, QUIC v2) — просто «SNI не извлечён»
        try
        {
            return ExtractCore(payload);
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractCore(byte[] p)
    {
        // Клиентский Initial обязан приходить в датаграмме >= 1200 байт (RFC 9000 §14.1)
        if (p is null || p.Length < 1200) return null;
        if ((p[0] & 0xC0) != 0xC0) return null;    // long header + fixed bit
        if ((p[0] & 0x30) != 0x00) return null;    // packet type: Initial
        uint version = (uint)((p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4]);
        if (version != 0x00000001) return null;    // только QUIC v1 (v2 использует другую соль)

        int pos = 5;
        int dcidLen = p[pos++];
        if (dcidLen > 20 || pos + dcidLen > p.Length) return null;
        var dcid = new byte[dcidLen];
        Array.Copy(p, pos, dcid, 0, dcidLen);
        pos += dcidLen;

        int scidLen = p[pos++];
        pos += scidLen;
        long tokenLen = ReadVarint(p, ref pos);
        pos += (int)tokenLen;
        long length = ReadVarint(p, ref pos);      // packet number + payload
        int pnOffset = pos;
        if (length < 20 || pnOffset + length > p.Length) return null;

        // Ключи клиентского Initial (RFC 9001 §5.2)
        Span<byte> initialSecret = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, dcid, InitialSaltV1, initialSecret);
        var clientSecret = HkdfExpandLabel(initialSecret, "client in", 32);
        var key = HkdfExpandLabel(clientSecret, "quic key", 16);
        var iv = HkdfExpandLabel(clientSecret, "quic iv", 12);
        var hp = HkdfExpandLabel(clientSecret, "quic hp", 16);

        // Снятие header protection (RFC 9001 §5.4): маска = AES-ECB(hp, sample)
        Span<byte> mask = stackalloc byte[16];
        using (var aes = Aes.Create())
        {
            aes.Key = hp;
            aes.EncryptEcb(p.AsSpan(pnOffset + 4, 16), mask, PaddingMode.None);
        }

        byte firstByte = (byte)(p[0] ^ (mask[0] & 0x0F));
        int pnLen = (firstByte & 0x03) + 1;
        long packetNumber = 0;
        var header = new byte[pnOffset + pnLen];   // AAD: заголовок с расшифрованным packet number
        Array.Copy(p, header, header.Length);
        header[0] = firstByte;
        for (int i = 0; i < pnLen; i++)
        {
            header[pnOffset + i] = (byte)(p[pnOffset + i] ^ mask[1 + i]);
            packetNumber = (packetNumber << 8) | header[pnOffset + i];
        }

        int cipherLen = (int)length - pnLen;
        if (cipherLen < 16) return null;

        var nonce = (byte[])iv.Clone();
        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(packetNumber >> (8 * i));

        var plain = new byte[cipherLen - 16];
        using (var gcm = new AesGcm(key, 16))
        {
            gcm.Decrypt(nonce,
                p.AsSpan(pnOffset + pnLen, cipherLen - 16),
                p.AsSpan(pnOffset + pnLen + cipherLen - 16, 16),
                plain, header);
        }

        var crypto = AssembleCryptoFrames(plain);
        return crypto is null ? null : TlsSniExtractor.TryExtractFromHandshake(crypto);
    }

    /// <summary>Собирает данные CRYPTO-фреймов в непрерывный блок от нулевого смещения.</summary>
    private static byte[]? AssembleCryptoFrames(byte[] plain)
    {
        var chunks = new List<(long Offset, int Start, int Length)>();
        int pos = 0;
        while (pos < plain.Length)
        {
            byte frameType = plain[pos];
            if (frameType == 0x00) { pos++; continue; }          // PADDING
            if (frameType == 0x01) { pos++; continue; }          // PING
            if (frameType == 0x02 || frameType == 0x03)          // ACK
            {
                pos++;
                ReadVarint(plain, ref pos);                      // Largest Acknowledged
                ReadVarint(plain, ref pos);                      // ACK Delay
                long rangeCount = ReadVarint(plain, ref pos);
                ReadVarint(plain, ref pos);                      // First ACK Range
                for (long i = 0; i < rangeCount; i++)
                {
                    ReadVarint(plain, ref pos);                  // Gap
                    ReadVarint(plain, ref pos);                  // ACK Range Length
                }
                if (frameType == 0x03)
                {
                    ReadVarint(plain, ref pos);                  // ECT0
                    ReadVarint(plain, ref pos);                  // ECT1
                    ReadVarint(plain, ref pos);                  // ECN-CE
                }
                continue;
            }
            if (frameType == 0x06)                               // CRYPTO
            {
                pos++;
                long offset = ReadVarint(plain, ref pos);
                long len = ReadVarint(plain, ref pos);
                if (len < 0 || pos + len > plain.Length) return null;
                chunks.Add((offset, pos, (int)len));
                pos += (int)len;
                continue;
            }
            break; // неизвестный фрейм — работаем с тем, что уже собрали
        }

        if (chunks.Count == 0) return null;
        chunks.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        if (chunks[0].Offset != 0) return null;

        var result = new List<byte>(chunks[0].Length);
        long contiguousEnd = 0;
        foreach (var (offset, start, len) in chunks)
        {
            if (offset > contiguousEnd) break;                   // разрыв — дальше не собрать
            int skip = (int)(contiguousEnd - offset);            // перекрытие чанков
            if (skip >= len) continue;
            for (int i = start + skip; i < start + len; i++)
                result.Add(plain[i]);
            contiguousEnd = offset + len;
        }
        return result.ToArray();
    }

    // HKDF-Expand-Label из TLS 1.3 (RFC 8446 §7.1) с пустым контекстом
    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, string label, int length)
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

    // Переменная длина QUIC (RFC 9000 §16): 2 старших бита задают длину поля
    private static long ReadVarint(byte[] data, ref int pos)
    {
        byte first = data[pos];
        int len = 1 << (first >> 6);
        long value = first & 0x3F;
        for (int i = 1; i < len; i++)
            value = (value << 8) | data[pos + i];
        pos += len;
        return value;
    }
}
