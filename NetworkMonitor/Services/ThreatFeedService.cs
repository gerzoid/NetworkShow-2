using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkMonitor.Services;

/// <summary>
/// Необязательный фид угроз: список IP управляющих серверов ботнетов (abuse.ch Feodo Tracker).
/// Выключен по умолчанию — приложение само ничего не скачивает. При включении раз в 12 часов делает один
/// HTTPS-запрос на feodotracker.abuse.ch, кэширует список в %APPDATA%\NetworkShow\threat-feed.txt.
/// </summary>
public sealed class ThreatFeedService : IDisposable
{
    public const string FeedUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
    private static readonly TimeSpan Interval = TimeSpan.FromHours(12);
    private static readonly string CachePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetworkShow", "threat-feed.txt");

    private readonly NotificationService _notify;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private CancellationTokenSource? _cts;

    public event EventHandler<string>? StatusChanged;

    public ThreatFeedService(NotificationService notify) => _notify = notify;

    public void Start()
    {
        if (_cts is not null) return;
        var cts = _cts = new CancellationTokenSource();
        _ = Task.Run(() => Loop(cts.Token));
    }

    public void Stop()
    {
        var cts = _cts;
        _cts = null;
        if (cts is null) return;
        try { cts.Cancel(); } catch { }
        cts.Dispose();
        _notify.SetThreatFeed(null);
    }

    public void Dispose()
    {
        Stop();
        _http.Dispose();
    }

    private async Task Loop(CancellationToken ct)
    {
        try
        {
            // Сначала кэш (без сети), затем обновление, если кэш старше интервала
            bool fresh = false;
            if (File.Exists(CachePath))
            {
                try
                {
                    _notify.SetThreatFeed(ParseIps(await File.ReadAllTextAsync(CachePath, ct).ConfigureAwait(false)));
                    fresh = DateTime.UtcNow - File.GetLastWriteTimeUtc(CachePath) < Interval;
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                if (!fresh) await Download(ct).ConfigureAwait(false);
                fresh = false;
                await Task.Delay(Interval, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task Download(CancellationToken ct)
    {
        try
        {
            var text = await _http.GetStringAsync(FeedUrl, ct).ConfigureAwait(false);
            var ips = ParseIps(text);
            if (ips.Count == 0) return;
            _notify.SetThreatFeed(ips);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
                await File.WriteAllTextAsync(CachePath, text, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch { }
            StatusChanged?.Invoke(this, $"Фид угроз обновлён: {ips.Count} адресов.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Фид угроз не загружен: {ex.Message}");
        }
    }

    public static HashSet<string> ParseIps(string text)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            if (System.Net.IPAddress.TryParse(line, out var ip)) set.Add(ip.ToString());
        }
        return set;
    }
}
