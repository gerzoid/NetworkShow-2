using System.Text;

namespace NetworkMonitor.Helpers;

public static class TlsSniExtractor
{
    public static string? TryExtract(byte[] payload)
    {
        if (payload is null || payload.Length < 43) return null;
        if (payload[0] != 0x16) return null;       // TLS record: Handshake
        if (payload[5] != 0x01) return null;       // Handshake type: ClientHello

        int pos = 9;                                // skip record header (5) + handshake header (4)
        pos += 2;                                   // ClientVersion
        pos += 32;                                  // Random
        if (pos >= payload.Length) return null;

        int sessLen = payload[pos++];
        pos += sessLen;
        if (pos + 2 > payload.Length) return null;

        int csLen = (payload[pos] << 8) | payload[pos + 1];
        pos += 2 + csLen;
        if (pos >= payload.Length) return null;

        int cmLen = payload[pos++];
        pos += cmLen;
        if (pos + 2 > payload.Length) return null;

        int extLen = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;
        int extEnd = System.Math.Min(pos + extLen, payload.Length);

        while (pos + 4 <= extEnd)
        {
            int extType = (payload[pos] << 8) | payload[pos + 1];
            int extDataLen = (payload[pos + 2] << 8) | payload[pos + 3];
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
                    int nameType = payload[p++];
                    int nameLen = (payload[p] << 8) | payload[p + 1];
                    p += 2;
                    if (p + nameLen > snEnd) return null;
                    if (nameType == 0x00) // host_name
                        return Encoding.ASCII.GetString(payload, p, nameLen);
                    p += nameLen;
                }
            }
            pos += extDataLen;
        }
        return null;
    }
}
