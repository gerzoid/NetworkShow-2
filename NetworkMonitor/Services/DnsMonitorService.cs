using System;
using System.Collections.Generic;
using System.Management;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetworkMonitor.Services;

/// <summary>
/// Источник DNS-имён с привязкой к процессу — независимо от транспорта, если запрос идёт через системный резолвер
/// (UDP/TCP 53, DoT/DoH системы Windows):
///  1) ETW-провайдер Microsoft-Windows-DNS-Client: события 3006 (запрос), 3020 (ответ + PID клиента), 3008 (результаты);
///  2) резерв, если ETW недоступен (нет прав администратора): опрос DNS-кэша Windows (WMI MSFT_DNSClientCache) —
///     даёт только соответствие «имя → IP», без процесса.
/// Не видит запросы, которые приложение шифрует и отправляет само (встроенный DoH в браузерах и т.п.).
/// Включается только вместе со сбором сайтов.
/// </summary>
public sealed class DnsMonitorService : IDisposable
{
    private const string SessionName = "NetworkShow-Dns";
    private static readonly Guid ProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private readonly ProcessResolverService _resolver;
    private readonly object _lock = new();
    private TraceEventSession? _session;
    private Task? _etwTask;
    private Timer? _cacheTimer;
    private readonly HashSet<string> _cacheSeen = new();
    private readonly Dictionary<string, long> _recentQueries = new();

    /// <summary>Запрос имени: (имя, PID клиента).</summary>
    public event Action<string, int>? Queried;
    /// <summary>Ответ: имя и полученные IP.</summary>
    public event Action<string, IReadOnlyList<string>>? Answered;
    public event Action<string>? StatusChanged;

    public bool EtwActive { get; private set; }
    public bool IsRunning { get; private set; }

    public DnsMonitorService(ProcessResolverService resolver) => _resolver = resolver;

    public string ProcessName(int pid) => pid > 0 ? _resolver.ResolvePidName(pid) : "unknown";

    public void Start()
    {
        lock (_lock)
        {
            if (IsRunning) return;
            IsRunning = true;
        }

        if (TryStartEtw())
        {
            EtwActive = true;
            StatusChanged?.Invoke("DNS: ETW-мониторинг запущен (имена с привязкой к процессу).");
            return;
        }

        EtwActive = false;
        _cacheTimer = new Timer(_ => PollCache(), null, 0, 60_000);
        StatusChanged?.Invoke("DNS: ETW недоступен (нужны права администратора) — используется DNS-кэш Windows (без процессов).");
    }

    public void Stop()
    {
        TraceEventSession? s;
        Task? t;
        Timer? timer;
        lock (_lock)
        {
            if (!IsRunning) return;
            IsRunning = false;
            EtwActive = false;
            s = _session; _session = null;
            t = _etwTask; _etwTask = null;
            timer = _cacheTimer; _cacheTimer = null;
            _cacheSeen.Clear();
            _recentQueries.Clear();
        }
        timer?.Dispose();
        try { s?.Stop(); } catch { }
        try { t?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { s?.Dispose(); } catch { }
    }

    public void Dispose() => Stop();

    // ───────────── ETW ─────────────

    private bool TryStartEtw()
    {
        try
        {
            try { TraceEventSession.GetActiveSession(SessionName)?.Stop(); } catch { }
            var session = new TraceEventSession(SessionName) { StopOnDispose = true };
            session.EnableProvider(ProviderGuid);

            var parser = new RegisteredTraceEventParser(session.Source);
            parser.All += OnEtwEvent;

            _session = session;
            _etwTask = Task.Run(() =>
            {
                try { session.Source.Process(); } catch { }
            });
            return true;
        }
        catch
        {
            try { _session?.Dispose(); } catch { }
            _session = null;
            return false;
        }
    }

    private void OnEtwEvent(TraceEvent data)
    {
        try
        {
            if (data.ProviderGuid != ProviderGuid) return;
            int id = (int)data.ID;
            if (id != 3006 && id != 3008 && id != 3020) return;

            var name = data.PayloadByName("QueryName") as string;
            if (string.IsNullOrEmpty(name)) return;
            name = Normalize(name);

            if (id == 3006 || id == 3020)
            {
                int pid = data.ProcessID;
                if (id == 3020 && data.PayloadByName("ClientPID") is { } cp) pid = Convert.ToInt32(cp);
                if (!IsDuplicateQuery(name, pid)) Queried?.Invoke(name, pid);
            }

            if (id == 3008 || id == 3020)
            {
                var ips = ParseResults(data.PayloadByName("QueryResults") as string);
                if (ips.Count > 0) Answered?.Invoke(name, ips);
            }
        }
        catch { }
    }

    // 3006 и 3020 описывают один и тот же запрос — не считаем его дважды
    private bool IsDuplicateQuery(string name, int pid)
    {
        long now = Environment.TickCount64;
        string key = pid + "|" + name;
        lock (_lock)
        {
            if (_recentQueries.TryGetValue(key, out var t) && now - t < 2000) return true;
            if (_recentQueries.Count > 4096) _recentQueries.Clear();
            _recentQueries[key] = now;
        }
        return false;
    }

    // ───────────── Резерв: DNS-кэш Windows ─────────────

    private void PollCache()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2",
                "SELECT Entry, Type, Data FROM MSFT_DNSClientCache");
            var batch = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementObject o in searcher.Get())
            {
                using (o)
                {
                    var type = Convert.ToInt32(o["Type"] ?? 0);
                    if (type != 1 && type != 28) continue;
                    var entry = o["Entry"] as string;
                    var data = o["Data"] as string;
                    if (string.IsNullOrEmpty(entry) || !IPAddress.TryParse(data, out var ip)) continue;
                    var name = Normalize(entry);
                    var ipText = ip.ToString();
                    if (!_cacheSeen.Add(name + "|" + ipText)) continue;
                    if (!batch.TryGetValue(name, out var list)) batch[name] = list = new List<string>();
                    list.Add(ipText);
                }
            }
            if (_cacheSeen.Count > 50_000) _cacheSeen.Clear();
            foreach (var kv in batch) Answered?.Invoke(kv.Key, kv.Value);
        }
        catch { }
    }

    // ───────────── Разбор ─────────────

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();

    /// <summary>Достаёт IP-адреса из строки результатов («1.2.3.4;5.6.7.8;» или «type: 5 cname;1.2.3.4;»).</summary>
    public static List<string> ParseResults(string? results)
    {
        var list = new List<string>();
        if (string.IsNullOrEmpty(results)) return list;
        foreach (var token in results.Split(new[] { ';', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            // «5» из «type: 5» IPAddress разбирает как 0.0.0.5 — нужны точки или двоеточия
            if ((token.Contains('.') || token.Contains(':')) && IPAddress.TryParse(token, out var ip) && !IPAddress.Any.Equals(ip) && !IPAddress.IPv6Any.Equals(ip))
                list.Add(ip.ToString());
        }
        return list;
    }
}
