using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Журналы Windows и их корреляция (нужны права администратора):
///  • 4624 — успешный сетевой (тип 3) или RDP (тип 10) вход с внешнего адреса — критично; RDP из LAN — предупреждение;
///    ночью (тихие часы) оценка повышается;
///  • 4625 — неудачные входы: N за 5 минут с одного источника — «подбор пароля»;
///  • корреляция: успешный вход после серии неудач с того же адреса или под той же учётной записью — критично;
///  • 4720 новая учётная запись, 4732 добавление в администраторы, 4740 блокировка учётной записи,
///    4698 новая задача планировщика, 7045 установка службы (журнал System), 1102 очистка журнала безопасности.
/// </summary>
public sealed class LogonMonitor : IDisposable
{
    private const string AdminsSid = "S-1-5-32-544";

    private readonly NotificationService _notify;
    private readonly object _lock = new();
    private EventLogWatcher? _security;
    private EventLogWatcher? _system;

    private readonly Dictionary<string, (long Start, int Count, long LastAlert)> _failures = new();
    private readonly Dictionary<string, List<long>> _recentFailures = new();
    private readonly Dictionary<string, long> _seen = new();

    public event EventHandler<string>? StatusChanged;

    /// <summary>Часы (локальное время), когда вход по сети считается необычным; подменяется в тестах.</summary>
    public Func<DateTime> LocalNow { get; set; } = () => DateTime.Now;
    public Func<long> Clock { get; set; } = () => Environment.TickCount64;

    public LogonMonitor(NotificationService notify) => _notify = notify;

    private static DetectionSettings S => SettingsService.Current.Detection;

    public void Start()
    {
        lock (_lock)
        {
            if (_security is null)
                _security = Watch("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732 or EventID=4740 or EventID=4698 or EventID=1102)]]");
            if (_system is null)
                _system = Watch("System", "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]");
        }
    }

    private EventLogWatcher? Watch(string log, string xpath)
    {
        try
        {
            var w = new EventLogWatcher(new EventLogQuery(log, PathType.LogName, xpath));
            w.EventRecordWritten += OnEvent;
            w.Enabled = true;
            return w;
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Журнал «{log}» недоступен (нужны права администратора): {ex.Message}");
            return null;
        }
    }

    public void Stop()
    {
        EventLogWatcher?[] ws;
        lock (_lock)
        {
            ws = new[] { _security, _system };
            _security = null;
            _system = null;
        }
        foreach (var w in ws)
        {
            if (w is null) continue;
            try { w.Enabled = false; w.EventRecordWritten -= OnEvent; w.Dispose(); } catch { }
        }
    }

    public void Dispose() => Stop();

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        using var rec = e.EventRecord;
        if (rec is null || !S.Enabled) return;
        try { Process(rec.Id, ReadData(rec)); }
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

    /// <summary>Обработка события по номеру и полям (вынесено для тестов).</summary>
    internal void Process(int id, Dictionary<string, string> d)
    {
        switch (id)
        {
            case 4624: OnLogonSuccess(d); break;
            case 4625: OnLogonFailure(d); break;
            case 4720:
                _notify.RaiseExternal(NotificationSeverity.Critical, "Создана учётная запись Windows",
                    $"Новая учётная запись «{Get(d, "TargetUserName")}» создана пользователем «{Get(d, "SubjectUserName")}». Если вы её не создавали — это признак взлома.");
                break;
            case 4732 when Get(d, "TargetSid") == AdminsSid:
                var member = Get(d, "MemberName");
                _notify.RaiseExternal(NotificationSeverity.Critical, "Пользователь добавлен в администраторы",
                    $"В группу администраторов добавлен «{(member is "" or "-" ? Get(d, "MemberSid") : member)}» (выполнил «{Get(d, "SubjectUserName")}»).");
                break;
            case 4740:
                _notify.RaiseExternal(NotificationSeverity.Warning, "Учётная запись заблокирована",
                    $"«{Get(d, "TargetUserName")}» заблокирована после неудачных входов" +
                    (Get(d, "TargetDomainName") is { Length: > 0 } c ? $" (источник: {c})" : string.Empty) + ".");
                break;
            case 4698:
                var task = Get(d, "TaskName");
                var who = Get(d, "SubjectUserName");
                // Служебные задачи Windows и ПО создаются постоянно — интересны только чужие
                if (task.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) || who.EndsWith('$') ||
                    who.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)) break;
                _notify.RaiseExternal(NotificationSeverity.Warning, "Создана задача планировщика",
                    $"«{task}» создана пользователем «{who}». Вредоносное ПО закрепляется в системе через планировщик.");
                break;
            case 7045:
                _notify.RaiseExternal(NotificationSeverity.Warning, "Установлена новая служба Windows",
                    $"«{Get(d, "ServiceName")}»: {Get(d, "ImagePath")} (учётная запись {Get(d, "AccountName")}). Если вы ничего не устанавливали — проверьте файл.");
                break;
            case 1102:
                _notify.RaiseExternal(NotificationSeverity.Critical, "Журнал безопасности очищен",
                    $"Журнал очистил «{Get(d, "SubjectUserName")}». Так скрывают следы взлома.");
                break;
        }
    }

    private bool InQuietHours()
    {
        int h = LocalNow().Hour;
        int a = S.QuietHoursStart, b = S.QuietHoursEnd;
        if (a == b) return false;
        return a < b ? h >= a && h < b : h >= a || h < b;
    }

    private void OnLogonSuccess(Dictionary<string, string> d)
    {
        var type = Get(d, "LogonType");
        if (type != "3" && type != "10") return;

        var ip = Get(d, "IpAddress");
        var user = Get(d, "TargetUserName");
        if (!IsRealAddress(ip)) return;
        if (user.EndsWith('$') || user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)) return;
        if (_notify.IsWhitelisted(ip)) return;

        long now = Clock();
        bool priv = NotificationService.IsLocalOrPrivate(ip);

        // Корреляция: успех после серии неудач
        int failsByIp, failsByUser;
        lock (_lock)
        {
            failsByIp = CountRecent("ip|" + ip, now);
            failsByUser = CountRecent("user|" + user.ToLowerInvariant(), now);
        }
        if (failsByIp >= 3 || failsByUser >= 3)
        {
            string key = $"{user}|{ip}|corr";
            if (Once(key, now, 600_000))
                _notify.RaiseExternal(NotificationSeverity.Critical, "Успешный вход после серии неудачных попыток",
                    $"«{user}» вошёл с {ip} ({(type == "10" ? "RDP" : "по сети")}) после {Math.Max(failsByIp, failsByUser)} неудачных попыток за 10 минут — возможно, пароль подобран.");
        }

        if (priv && type == "3") return; // обычные сетевые входы из LAN — шум

        bool quiet = InQuietHours();
        if (!Once($"{user}|{ip}|{type}", now, priv ? 1_800_000 : 600_000)) return;

        string how = type == "10" ? "RDP (удалённый рабочий стол)" : "сетевой вход";
        var sev = !priv || quiet ? NotificationSeverity.Critical : NotificationSeverity.Warning;
        _notify.RaiseExternal(sev, "Вход в Windows по сети",
            $"Пользователь «{user}» вошёл: {how}, источник {ip}" + (priv ? " (локальная сеть)" : " (внешний адрес)") +
            (quiet ? " — в тихие часы (ночью)" : string.Empty));
    }

    private void OnLogonFailure(Dictionary<string, string> d)
    {
        var ip = Get(d, "IpAddress");
        var user = Get(d, "TargetUserName");
        string source = IsRealAddress(ip) ? ip : $"локально:{user}";
        if (IsRealAddress(ip) && _notify.IsWhitelisted(ip)) return;

        int threshold = Math.Max(2, S.FailedLogonThreshold);
        long now = Clock();
        int count;
        lock (_lock)
        {
            // Для корреляции с последующим успехом
            if (IsRealAddress(ip)) AddRecent("ip|" + ip, now);
            AddRecent("user|" + user.ToLowerInvariant(), now);

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

    private void AddRecent(string key, long now)
    {
        if (!_recentFailures.TryGetValue(key, out var list))
        {
            if (_recentFailures.Count > 5000) _recentFailures.Clear();
            _recentFailures[key] = list = new List<long>();
        }
        list.Add(now);
        if (list.Count > 50) list.RemoveAt(0);
    }

    private int CountRecent(string key, long now) =>
        _recentFailures.TryGetValue(key, out var list) ? list.Count(t => now - t <= 600_000) : 0;

    private bool Once(string key, long now, long ttlMs)
    {
        lock (_lock)
        {
            if (_seen.TryGetValue(key, out var last) && now - last < ttlMs) return false;
            if (_seen.Count > 5000) _seen.Clear();
            _seen[key] = now;
            return true;
        }
    }
}
