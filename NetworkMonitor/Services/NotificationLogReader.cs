using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>Восстанавливает журнал уведомлений в окне из notifications.log, чтобы он не пропадал при перезапуске.</summary>
public static class NotificationLogReader
{
    /// <summary>Последние <paramref name="max"/> уведомлений, самые новые — первыми.</summary>
    public static List<TrafficNotification> ReadRecent(string path, int max)
    {
        var result = new List<TrafficNotification>();
        if (!File.Exists(path) || max <= 0) return result;

        var tail = new Queue<string>(max + 1);
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8);
            string? line;
            while ((line = sr.ReadLine()) is not null)
            {
                if (line.Length == 0) continue;
                tail.Enqueue(line);
                if (tail.Count > max) tail.Dequeue();
            }
        }
        catch { return result; }

        foreach (var line in tail)
            if (TryParse(line, out var n)) result.Add(n);
        result.Reverse();
        return result;
    }

    /// <summary>Формат строки: [2026-11-21T12:27:56.2039346+08:00] [Warning] Заголовок: сообщение.</summary>
    public static bool TryParse(string line, out TrafficNotification notification)
    {
        notification = null!;
        if (line.Length < 8 || line[0] != '[') return false;
        int e1 = line.IndexOf(']');
        if (e1 < 2 || !DateTimeOffset.TryParse(line.AsSpan(1, e1 - 1), CultureInfo.InvariantCulture, DateTimeStyles.None, out var ts)) return false;

        int s2 = line.IndexOf('[', e1);
        int e2 = s2 < 0 ? -1 : line.IndexOf(']', s2);
        if (s2 < 0 || e2 < 0 || !Enum.TryParse<NotificationSeverity>(line.AsSpan(s2 + 1, e2 - s2 - 1), out var sev)) return false;

        var rest = line[(e2 + 1)..].TrimStart();
        string title = rest, message = string.Empty;
        int colon = rest.IndexOf(": ", StringComparison.Ordinal);
        if (colon > 0)
        {
            title = rest[..colon];
            message = rest[(colon + 2)..];
        }
        notification = new TrafficNotification { Timestamp = ts.LocalDateTime, Severity = sev, Title = title, Message = message };
        return true;
    }
}
