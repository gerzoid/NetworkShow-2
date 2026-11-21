using System;
using System.Text;

namespace NetworkMonitor.Helpers;

/// <summary>Разбор имени из DNS-запроса (UDP-датаграмма, клиент → резолвер) без аллокаций на отбракованных пакетах.</summary>
public static class DnsQueryParser
{
    /// <summary>true — это запрос (QR=0) с одним вопросом; <paramref name="name"/> в нижнем регистре без завершающей точки.</summary>
    public static bool TryParse(ReadOnlySpan<byte> dns, out string name, out ushort qtype)
    {
        name = string.Empty;
        qtype = 0;
        if (dns.Length < 17) return false;
        if ((dns[2] & 0x80) != 0) return false;                 // ответ, а не запрос
        if (((dns[2] >> 3) & 0x0F) != 0) return false;           // только стандартный QUERY
        int qd = (dns[4] << 8) | dns[5];
        if (qd < 1) return false;

        Span<char> buf = stackalloc char[255];
        int len = 0, pos = 12;
        while (true)
        {
            if (pos >= dns.Length) return false;
            int l = dns[pos++];
            if (l == 0) break;
            if ((l & 0xC0) != 0) return false;                   // указатели в вопросе не ожидаются
            if (pos + l > dns.Length) return false;
            if (len + l + 1 > buf.Length) return false;
            if (len > 0) buf[len++] = '.';
            for (int i = 0; i < l; i++)
            {
                byte b = dns[pos + i];
                if (b < 0x21 || b > 0x7E) return false;          // не печатный ASCII — не имя хоста
                buf[len++] = b is >= (byte)'A' and <= (byte)'Z' ? (char)(b + 32) : (char)b;
            }
            pos += l;
        }
        if (len == 0 || pos + 4 > dns.Length) return false;
        qtype = (ushort)((dns[pos] << 8) | dns[pos + 1]);
        name = new string(buf[..len]);
        return true;
    }

    /// <summary>Энтропия Шеннона (бит/символ) строки.</summary>
    public static double Entropy(ReadOnlySpan<char> s)
    {
        if (s.IsEmpty) return 0;
        Span<int> counts = stackalloc int[128];
        int total = 0;
        foreach (var c in s)
        {
            if (c < 128) { counts[c]++; total++; }
        }
        if (total == 0) return 0;
        double h = 0;
        foreach (var n in counts)
        {
            if (n == 0) continue;
            double p = (double)n / total;
            h -= p * Math.Log2(p);
        }
        return h;
    }

    /// <summary>Регистрируемая часть: последние две метки (a.b.example.com → example.com; для co.uk — приближённо).</summary>
    public static string BaseDomain(string name, out string subLabel)
    {
        int last = name.LastIndexOf('.');
        if (last <= 0) { subLabel = string.Empty; return name; }
        int prev = name.LastIndexOf('.', last - 1);
        if (prev < 0) { subLabel = string.Empty; return name; }
        subLabel = name[..prev];
        return name[(prev + 1)..];
    }
}
