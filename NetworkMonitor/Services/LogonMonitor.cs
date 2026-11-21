using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Входы в Windows по журналу безопасности:
///  • 4624 — успешный вход по сети (тип 3) или через RDP (тип 10) с внешнего адреса — критично;
///    RDP из локальной сети — предупреждение; сетевые входы из LAN не показываются (их видно в «Доступе к шарам»);
///  • 4625 — неудачные входы: N за 5 минут с одного источника — «подбор пароля».
/// Журнал «Безопасность» читается только от администратора; иначе мониторинг недоступен (сообщение в статусе).
/// </summary>
public sealed class LogonMonitor : IDisposable
{
    private readonly NotificationService _notify;
    private readonly object _lock = new();
    private EventLogWatcher? _watcher;

    private readonly Dictionary<string, (long Start, int Count, long LastAlert)> _failures = new();
    private readonly Dictionary<string, long> _seen = new();

    public event EventHandler<string>? StatusChanged;

    public LogonMonitor(NotificationService notify) => _notify = notify;

    public void Start()
    {
        lock (_lock)
        {
            if (_watcher is not null) return;
            try
            {
                var query = new EventLogQuery("Security", PathType.LogName,
                    "*[System[(EventID=4624 or EventID=4625)]]");
                var w = new EventLogWatcher(query);
                w.EventRecordWritten += OnEvent;
                w.Enabled = true;
                _watcher = w;
            }
            catch (Exception ex)
            {
                _watcher = null;
                StatusChanged?.Invoke(this, $"Мониторинг входов Windows недоступен (нужны права администратора): {ex.Message}");
            }
        }
    }

    public void Stop()
    {
        EventLogWatcher? w;
        lock (_lock)
        {
            w = _watcher;
            _watcher = null;
        }
        if (w is null) return;
        try
        {
            w.Enabled = false;
            w.EventRecordWritten -= OnEvent;
            w.Dispose();
        }
        catch { }
    }

    public void Dispose() => Stop();

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        using var rec = e.EventRecord;
        if (rec is null || !SettingsService.Current.Detection.Enabled) return;
        try
        {
            var data = ReadData(rec);
            if (rec.Id == 4624) OnLogonSuccess(data);
            else if (rec.Id == 4625) OnLogonFailure(data);
        }
        catch { }
    }

    private static Dictionary<string, string> ReadData(EventRecord rec)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var doc = XDocument.Parse(rec.ToXml());
        foreach (var el in doc.Descendants().Where(x => x.Name.LocalName == "Data"))
        {
            var name = (string?)el.Attribute("Name");
            if (!string.IsNullOrEmpty(name)) d[name] = el.Value;
        }
        return d;
    }

    private static string Get(Dictionary<string, string> d, string key) =>
        d.TryGetValue(key, out var v) ? v.Trim() : string.Empty;

    private static bool IsRealAddress(string ip) =>
        ip.Length > 0 && ip != "-" && ip != "::1" && !ip.StartsWith("127.", StringComparison.Ordinal);

    private void OnLogonSuccess(Dictionary<string, string> d)
    {
        var type = Get(d, "LogonType");
        if (type != "3" && type != "10") return;

        var ip = Get(d, "IpAddress");
        var user = Get(d, "TargetUserName");
        if (!IsRealAddress(ip)) return;
        if (user.EndsWith('$') || user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)) return;
        if (_notify.IsWhitelisted(ip)) return;

        bool priv = NotificationService.IsLocalOrPrivate(ip);
        if (priv && type == "3") return;

        string key = $"{user}|{ip}|{type}";
        long now = Environment.TickCount64;
        lock (_lock)
        {
            if (_seen.TryGetValue(key, out var last) && now - last < 600_000) return;
            if (_seen.Count > 5000) _seen.Clear();
            _seen[key] = now;
        }

        string how = type == "10" ? "RDP (удалённый рабочий стол)" : "сетевой вход";
        _notify.RaiseExternal(priv ? NotificationSeverity.Warning : NotificationSeverity.Critical,
            "Вход в Windows по сети",
            $"Пользователь «{user}» вошёл: {how}, источник {ip}" + (priv ? " (локальная сеть)" : " (внешний адрес)"));
    }

    private void OnLogonFailure(Dictionary<string, string> d)
    {
        var ip = Get(d, "IpAddress");
        var user = Get(d, "TargetUserName");
        string source = IsRealAddress(ip) ? ip : $"локально:{user}";
        if (IsRealAddress(ip) && _notify.IsWhitelisted(ip)) return;

        int threshold = Math.Max(2, SettingsService.Current.Detection.FailedLogonThreshold);
        long now = Environment.TickCount64;
        int count;
        lock (_lock)
        {
            _failures.TryGetValue(source, out var st);
            if (st.Start == 0 || now - st.Start > 300_000) st = (now, 0, st.LastAlert);
            st.Count++;
            count = st.Count;
            if (count >= threshold && (st.LastAlert == 0 || now - st.LastAlert > 300_000))
                st.LastAlert = now;
            else
                count = 0; // тревоги не будет
            if (_failures.Count > 5000) _failures.Clear();
            _failures[source] = st;
        }
        if (count == 0) return;

        _notify.RaiseExternal(NotificationSeverity.Critical, "Подбор пароля Windows",
            $"{count} неудачных входов за 5 мин, источник {(IsRealAddress(ip) ? ip : "этот ПК")}, последняя учётная запись «{user}»");
    }
}
