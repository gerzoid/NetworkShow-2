using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace NetworkMonitor.Services;

[Flags]
public enum CleanupKinds
{
    None = 0,
    /// <summary>Логи трафика traffic_*.jsonl / traffic_*.csv.</summary>
    TrafficLogs = 1,
    /// <summary>Экспорты: connections_*.json|csv, analytics_*.csv.</summary>
    Exports = 2,
    /// <summary>Строки журнала notifications.log.</summary>
    NotificationLog = 4,
    /// <summary>crash.log.</summary>
    CrashLog = 8,
    All = TrafficLogs | Exports | NotificationLog | CrashLog
}

/// <param name="Files">Удалено (или будет удалено) файлов.</param>
/// <param name="Bytes">Их общий размер.</param>
/// <param name="NotificationLines">Строк журнала уведомлений.</param>
/// <param name="Skipped">Файлов, которые не удалось удалить (используются программой).</param>
public sealed record CleanupResult(int Files, long Bytes, int NotificationLines, int Skipped);

/// <summary>Очистка накопленных на диске данных за период: логи трафика, журнал уведомлений, экспорты, crash.log.</summary>
public static class DataCleanupService
{
    public static string DefaultDir => Path.Combine(AppContext.BaseDirectory, "logs");

    private static readonly string[] TrafficPatterns = { "traffic_*.jsonl", "traffic_*.csv" };
    private static readonly string[] ExportPatterns = { "connections_*.json", "connections_*.csv", "analytics_*.csv" };

    /// <summary>Что будет удалено (ничего не меняет). <paramref name="olderThan"/> null — всё.</summary>
    public static CleanupResult Preview(string dir, TimeSpan? olderThan, CleanupKinds kinds, DateTime? now = null) =>
        Run(dir, olderThan, kinds, now ?? DateTime.Now, dryRun: true);

    public static CleanupResult Execute(string dir, TimeSpan? olderThan, CleanupKinds kinds, DateTime? now = null) =>
        Run(dir, olderThan, kinds, now ?? DateTime.Now, dryRun: false);

    private static CleanupResult Run(string dir, TimeSpan? olderThan, CleanupKinds kinds, DateTime now, bool dryRun)
    {
        if (!Directory.Exists(dir)) return new CleanupResult(0, 0, 0, 0);

        // «Всё»: граница в будущем, любой файл старше неё
        DateTime cutoff = olderThan is null ? DateTime.MaxValue : now - olderThan.Value;
        int files = 0, lines = 0, skipped = 0;
        long bytes = 0;

        var patterns = new List<string>();
        if (kinds.HasFlag(CleanupKinds.TrafficLogs)) patterns.AddRange(TrafficPatterns);
        if (kinds.HasFlag(CleanupKinds.Exports)) patterns.AddRange(ExportPatterns);
        if (kinds.HasFlag(CleanupKinds.CrashLog)) patterns.Add("crash.log");

        foreach (var path in patterns.SelectMany(p => Directory.EnumerateFiles(dir, p)).Distinct())
        {
            var fi = new FileInfo(path);
            if (fi.LastWriteTime >= cutoff) continue;
            if (dryRun) { files++; bytes += fi.Length; continue; }
            try
            {
                long len = fi.Length;
                fi.Delete();
                files++;
                bytes += len;
            }
            catch (IOException) { skipped++; }
            catch (UnauthorizedAccessException) { skipped++; }
        }

        if (kinds.HasFlag(CleanupKinds.NotificationLog))
        {
            var log = Path.Combine(dir, "notifications.log");
            if (File.Exists(log)) lines += TrimNotifications(log, cutoff, dryRun, ref skipped);
        }
        return new CleanupResult(files, bytes, lines, skipped);
    }

    /// <summary>Удаляет строки журнала старше границы; строки без читаемой даты сохраняются. Возвращает число удалённых строк.</summary>
    private static int TrimNotifications(string path, DateTime cutoff, bool dryRun, ref int skipped)
    {
        try
        {
            string[] all;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var sr = new StreamReader(fs, Encoding.UTF8))
                all = sr.ReadToEnd().Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            var kept = new List<string>(all.Length);
            int removed = 0;
            foreach (var line in all)
            {
                if (line.Length == 0) continue;
                if (IsOlder(line, cutoff)) removed++;
                else kept.Add(line);
            }
            if (removed == 0 || dryRun) return removed;

            File.WriteAllText(path, kept.Count == 0 ? string.Empty : string.Join(Environment.NewLine, kept) + Environment.NewLine,
                new UTF8Encoding(true));
            return removed;
        }
        catch (IOException) { skipped++; return 0; }
        catch (UnauthorizedAccessException) { skipped++; return 0; }
    }

    private static bool IsOlder(string line, DateTime cutoff)
    {
        // Формат: [2026-11-21T12:27:56.2039346+08:00] [Info] ...
        if (line.Length < 3 || line[0] != '[') return false;
        int end = line.IndexOf(']');
        if (end < 2) return false;
        return DateTimeOffset.TryParse(line.AsSpan(1, end - 1), CultureInfo.InvariantCulture, DateTimeStyles.None, out var ts)
               && ts.LocalDateTime < cutoff;
    }
}
