using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Net;
using System.Threading;
using System.Xml.Linq;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Мониторинг входящего доступа к SMB-шарам этого ПК:
///  1) живой опрос SMB-сессий и открытых файлов (WMI, root\Microsoft\Windows\SMB) — работает без аудита;
///  2) журнал безопасности Windows: 5140 (подключение к шаре), 5145 (запрос доступа к файлу, в т.ч. отказы),
///     4625 (неудачный сетевой вход) — требует включённого аудита «File Share» / «Detailed File Share».
/// Подключения через SSH-туннели приходят с 127.0.0.1/адреса самого ПК; для них определяется процесс-владелец
/// клиентского сокета (ssh.exe и т.п.) по таблице TCP.
/// </summary>
public sealed class ShareAccessMonitor : IDisposable
{
    private const int SmbPort = 445;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(3);

    private readonly object _lock = new();
    private Timer? _pollTimer;
    private EventLogWatcher? _watcher;
    private volatile bool _running;
    private int _polling;

    private readonly HashSet<string> _knownSessions = new();
    private readonly HashSet<string> _knownOpens = new();
    private readonly Dictionary<string, DateTime> _recent = new();
    private HashSet<IPAddress> _localAddrs = new();

    public event EventHandler<ShareAccessEvent>? EventReceived;
    public event EventHandler<string>? StatusChanged;

    public bool IsRunning => _running;
    public bool AuditWatcherActive => _watcher is not null;

    public enum AuditState { Unknown, Off, Partial, On }

    public static AuditState GetAuditState()
    {
        var fs = AuditPolicyHelper.Query(AuditPolicyHelper.FileShare);
        var dfs = AuditPolicyHelper.Query(AuditPolicyHelper.DetailedFileShare);
        if (fs is null || dfs is null) return AuditState.Unknown;
        if (fs == 3 && dfs == 3) return AuditState.On;
        if (fs == 0 && dfs == 0) return AuditState.Off;
        return AuditState.Partial;
    }

    /// <summary>Включает аудит File Share, Detailed File Share и Logon (успехи и отказы).</summary>
    public static bool EnableAudit()
    {
        bool ok = AuditPolicyHelper.EnableSuccessAndFailure(AuditPolicyHelper.FileShare);
        ok &= AuditPolicyHelper.EnableSuccessAndFailure(AuditPolicyHelper.DetailedFileShare);
        // 4625 пишется подкатегорией Logon; отказы обычно уже включены, ошибку не считаем фатальной
        AuditPolicyHelper.EnableSuccessAndFailure(AuditPolicyHelper.Logon);
        return ok;
    }

    public void Start()
    {
        if (_running) return;
        _running = true;
        _knownSessions.Clear();
        _knownOpens.Clear();

        StartAuditWatcher();
        _pollTimer = new Timer(_ => Poll(), null, 0, (int)PollInterval.TotalMilliseconds);
        StatusChanged?.Invoke(this, _watcher is not null
            ? "Мониторинг шар запущен (живые сессии + журнал аудита)."
            : "Мониторинг шар запущен (только живые сессии; аудит недоступен или выключен).");
    }

    public void Stop()
    {
        if (!_running) return;
        _running = false;
        using (var wh = new ManualResetEvent(false))
        {
            if (_pollTimer is not null && _pollTimer.Dispose(wh)) wh.WaitOne(2000);
        }
        _pollTimer = null;
        StopAuditWatcher();
        StatusChanged?.Invoke(this, "Мониторинг шар остановлен.");
    }

    /// <summary>Перезапустить подписку на журнал (после включения аудита).</summary>
    public void RestartAuditWatcher()
    {
        StopAuditWatcher();
        if (_running) StartAuditWatcher();
    }

    // ───────────── Журнал безопасности ─────────────

    private void StartAuditWatcher()
    {
        if (_watcher is not null) return;
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=5140 or EventID=5145 or EventID=4625)]]");
            var w = new EventLogWatcher(query);
            w.EventRecordWritten += OnSecurityEvent;
            w.Enabled = true;
            _watcher = w;
        }
        catch (Exception ex)
        {
            _watcher = null;
            StatusChanged?.Invoke(this, $"Журнал безопасности недоступен: {ex.Message}");
        }
    }

    private void StopAuditWatcher()
    {
        var w = _watcher;
        _watcher = null;
        if (w is null) return;
        try
        {
            w.Enabled = false;
            w.EventRecordWritten -= OnSecurityEvent;
            w.Dispose();
        }
        catch { }
    }

    private void OnSecurityEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        using var rec = e.EventRecord;
        if (rec is null) return;
        try
        {
            var ev = ParseSecurityEvent(rec);
            if (ev is not null) Emit(ev);
        }
        catch { }
    }

    private ShareAccessEvent? ParseSecurityEvent(EventRecord rec)
    {
        var xml = XDocument.Parse(rec.ToXml());
        var data = xml.Descendants().Where(x => x.Name.LocalName == "Data" && x.Attribute("Name") != null)
            .GroupBy(x => x.Attribute("Name")!.Value)
            .ToDictionary(g => g.Key, g => g.First().Value.Trim());
        string D(string k) => data.TryGetValue(k, out var v) ? v : string.Empty;

        bool failure = ((rec.Keywords ?? 0) & (long)StandardEventKeywords.AuditFailure) != 0;
        var time = rec.TimeCreated ?? DateTime.Now;
        string client = CleanIp(D("IpAddress"));
        string port = D("IpPort");
        if (port == "0" || port == "-") port = string.Empty;
        string user = FormatUser(D("SubjectDomainName"), D("SubjectUserName"));

        switch (rec.Id)
        {
            case 4625:
            {
                if (D("LogonType") != "3") return null;
                return Decorate(new ShareAccessEvent
                {
                    Timestamp = time,
                    Kind = ShareEventKind.LogonFailed,
                    Client = client,
                    ClientPort = port,
                    User = FormatUser(D("TargetDomainName"), D("TargetUserName")),
                    Access = "Вход",
                    Path = string.IsNullOrEmpty(D("WorkstationName")) ? string.Empty : $"станция {D("WorkstationName")}",
                    Denied = true,
                    Source = "Аудит"
                });
            }
            case 5140:
            {
                var share = D("ShareName");
                return Decorate(new ShareAccessEvent
                {
                    Timestamp = time,
                    Kind = ShareEventKind.Session,
                    Client = client,
                    ClientPort = port,
                    User = user,
                    Share = CleanShare(share),
                    Path = D("ShareLocalPath"),
                    Access = "Подключение",
                    Denied = failure,
                    Source = "Аудит"
                });
            }
            case 5145:
            {
                var share = CleanShare(D("ShareName"));
                // Каналы IPC$ (srvsvc, wkssvc…) — служебный шум; интересны только отказы
                if (!failure && share.Equals("IPC$", StringComparison.OrdinalIgnoreCase)) return null;
                return Decorate(new ShareAccessEvent
                {
                    Timestamp = time,
                    Kind = ShareEventKind.FileAccess,
                    Client = client,
                    ClientPort = port,
                    User = user,
                    Share = share,
                    Path = D("RelativeTargetName"),
                    Access = DescribeMask(D("AccessMask")),
                    Denied = failure,
                    Source = "Аудит"
                });
            }
            default:
                return null;
        }
    }

    // ───────────── Живой опрос SMB ─────────────

    private void Poll()
    {
        if (!_running) return;
        if (Interlocked.Exchange(ref _polling, 1) == 1) return;
        try
        {
            _localAddrs = GetLocalAddresses();
            var shares = LoadShares();
            // При активном аудите те же обращения придут из журнала — живой опрос только запоминает состояние
            bool suppress = _watcher is not null;

            var seenSessions = new HashSet<string>();
            using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\SMB",
                       "SELECT SessionId, ClientComputerName, ClientUserName FROM MSFT_SmbSession"))
            using (var results = s.Get())
            {
                foreach (ManagementObject o in results)
                {
                    using (o)
                    {
                        string id = Convert.ToString(o["SessionId"], CultureInfo.InvariantCulture) ?? "";
                        seenSessions.Add(id);
                        if (!_knownSessions.Add(id) || suppress) continue;
                        string client = CleanIp(Convert.ToString(o["ClientComputerName"]) ?? "");
                        Emit(Decorate(new ShareAccessEvent
                        {
                            Kind = ShareEventKind.Session,
                            Client = client,
                            User = Convert.ToString(o["ClientUserName"]) ?? "",
                            Access = "Подключение",
                            Source = "Сессия"
                        }));
                    }
                }
            }
            _knownSessions.IntersectWith(seenSessions);

            var seenOpens = new HashSet<string>();
            using (var s = new ManagementObjectSearcher(@"root\Microsoft\Windows\SMB",
                       "SELECT FileId, SessionId, ClientComputerName, ClientUserName, Path, ShareRelativePath FROM MSFT_SmbOpenFile"))
            using (var results = s.Get())
            {
                foreach (ManagementObject o in results)
                {
                    using (o)
                    {
                        string key = $"{o["SessionId"]}:{o["FileId"]}";
                        seenOpens.Add(key);
                        if (!_knownOpens.Add(key) || suppress) continue;
                        string path = Convert.ToString(o["Path"]) ?? "";
                        string rel = Convert.ToString(o["ShareRelativePath"]) ?? "";
                        Emit(Decorate(new ShareAccessEvent
                        {
                            Kind = ShareEventKind.OpenFile,
                            Client = CleanIp(Convert.ToString(o["ClientComputerName"]) ?? ""),
                            User = Convert.ToString(o["ClientUserName"]) ?? "",
                            Share = MatchShare(shares, path),
                            Path = string.IsNullOrEmpty(rel) ? path : rel,
                            Access = "Открыт",
                            Source = "Открыт"
                        }));
                    }
                }
            }
            _knownOpens.IntersectWith(seenOpens);
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Опрос SMB: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _polling, 0);
        }
    }

    private static List<(string Name, string Path)> LoadShares()
    {
        var list = new List<(string, string)>();
        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name, Path FROM Win32_Share");
            using var results = s.Get();
            foreach (ManagementObject o in results)
            {
                using (o)
                {
                    var p = Convert.ToString(o["Path"]);
                    if (!string.IsNullOrEmpty(p)) list.Add((Convert.ToString(o["Name"]) ?? "", p));
                }
            }
        }
        catch { }
        return list;
    }

    private static string MatchShare(List<(string Name, string Path)> shares, string path)
    {
        string best = "";
        int bestLen = -1;
        foreach (var (name, p) in shares)
        {
            if (path.StartsWith(p, StringComparison.OrdinalIgnoreCase) && p.Length > bestLen)
            {
                best = name;
                bestLen = p.Length;
            }
        }
        return best;
    }

    // ───────────── Общие помощники ─────────────

    /// <summary>Если клиент — этот же ПК (loopback / свой адрес), это туннель: ищем процесс, держащий клиентский сокет к :445.</summary>
    private ShareAccessEvent Decorate(ShareAccessEvent ev)
    {
        if (!IsLocalOrigin(ev.Client)) return ev;
        int? port = int.TryParse(ev.ClientPort, out var p) && p > 0 ? p : null;
        string via = FindTunnelProcess(port);
        return new ShareAccessEvent
        {
            Timestamp = ev.Timestamp,
            Kind = ev.Kind,
            Client = ev.Client,
            ClientPort = ev.ClientPort,
            User = ev.User,
            Share = ev.Share,
            Path = ev.Path,
            Access = ev.Access,
            Denied = ev.Denied,
            Source = ev.Source,
            Via = string.IsNullOrEmpty(via) ? "локально / туннель" : via
        };
    }

    private bool IsLocalOrigin(string client)
    {
        if (string.IsNullOrEmpty(client)) return false;
        if (client.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase)) return true;
        if (!IPAddress.TryParse(client, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return _localAddrs.Contains(ip);
    }

    private static string FindTunnelProcess(int? clientPort)
    {
        var names = new List<string>();
        foreach (var row in TcpTableReader.Read())
        {
            // Клиентская сторона соединения к SMB-серверу этого же ПК: remote = :445, local = исходящий порт
            if (row.RemotePort != SmbPort) continue;
            if (clientPort is int cp && row.LocalPort != cp) continue;
            if (!IPAddress.IsLoopback(row.RemoteAddr) && !row.LocalAddr.Equals(row.RemoteAddr)) continue;
            if (row.Pid <= 4) continue;
            var name = NativeProcess.TryGetProcessName(row.Pid) ?? "?";
            var text = $"{name} (PID {row.Pid})";
            if (!names.Contains(text)) names.Add(text);
        }
        return string.Join(", ", names);
    }

    private static HashSet<IPAddress> GetLocalAddresses()
    {
        var set = new HashSet<IPAddress>();
        try
        {
            foreach (var a in Dns.GetHostAddresses(Dns.GetHostName()))
                set.Add(a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a);
        }
        catch { }
        return set;
    }

    private void Emit(ShareAccessEvent ev)
    {
        // SMB на один файл шлёт десятки запросов — склеиваем одинаковые события за короткое окно
        string key = $"{ev.Kind}|{ev.Client}|{ev.User}|{ev.Share}|{ev.Path}|{ev.Access}|{ev.Denied}";
        var now = DateTime.UtcNow;
        lock (_lock)
        {
            if (_recent.TryGetValue(key, out var last) && now - last < DedupWindow) return;
            _recent[key] = now;
            if (_recent.Count > 2000)
            {
                foreach (var k in _recent.Where(kv => now - kv.Value > DedupWindow).Select(kv => kv.Key).ToList())
                    _recent.Remove(k);
            }
        }
        EventReceived?.Invoke(this, ev);
    }

    private static string CleanIp(string s)
    {
        s = s.Trim();
        if (s is "-" or "") return string.Empty;
        int pct = s.IndexOf('%');
        if (pct > 0) s = s[..pct];
        if (IPAddress.TryParse(s, out var ip) && ip.IsIPv4MappedToIPv6) s = ip.MapToIPv4().ToString();
        return s;
    }

    private static string CleanShare(string s) => s.Replace(@"\\*\", "").Trim();

    private static string FormatUser(string domain, string user)
    {
        if (string.IsNullOrEmpty(user) || user == "-") return string.Empty;
        return string.IsNullOrEmpty(domain) || domain == "-" ? user : $"{domain}\\{user}";
    }

    private static string DescribeMask(string maskText)
    {
        if (string.IsNullOrEmpty(maskText)) return "?";
        try
        {
            uint m = Convert.ToUInt32(maskText.Replace("0x", ""), 16);
            var parts = new List<string>();
            if ((m & 0x1) != 0 || (m & 0x20) != 0) parts.Add("Чтение");
            if ((m & 0x2) != 0 || (m & 0x4) != 0 || (m & 0x10) != 0 || (m & 0x100) != 0) parts.Add("Запись");
            if ((m & 0x10000) != 0 || (m & 0x40) != 0) parts.Add("Удаление");
            if ((m & 0xC0000) != 0) parts.Add("Права");
            if (parts.Count == 0) parts.Add("Метаданные");
            return string.Join(", ", parts);
        }
        catch { return maskText; }
    }

    public void Dispose() => Stop();
}
