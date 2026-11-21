using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Эвристические детекторы аномалий по потоку пакетов (вызывается из потока потребителя):
///  • входящие SYN на чувствительные порты с внешних адресов;
///  • сканирование портов (много разных портов с одного IP за окно);
///  • подбор пароля (частые подключения к служебному порту);
///  • beaconing (подключения к одной цели с почти равными интервалами);
///  • всплеск исходящего трафика процесса относительно его скользящей нормы (EWMA + σ);
///  • новый процесс в сети и выход в сеть «системных утилит» (powershell, rundll32…);
///  • новые слушающие порты (опрос раз в 30 с).
/// Пороги — в <see cref="DetectionSettings"/>. Адреса из белого списка игнорируются.
/// Детекторы — подсказки, а не доказательства: периодический трафик бывает легитимным.
/// </summary>
public sealed class AnomalyDetectionService : IDisposable
{
    private const int BucketMs = 5_000;
    private const int WarmupBuckets = 60;
    private const int MaxEntries = 20_000;
    // «тревоги ещё не было»: не 0, иначе в первый час после загрузки ПК (TickCount64 мал) тревоги подавлялись бы
    private const long Never = long.MinValue / 4;

    private static readonly HashSet<int> CriticalPorts = new() { 22, 23, 445, 3389, 5900 };
    private static readonly HashSet<int> SensitivePorts = new()
    {
        21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986
    };
    private static readonly HashSet<int> AuthPorts = new() { 21, 22, 23, 445, 3389, 5900, 5985, 5986 };
    private static readonly HashSet<string> Lolbins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
        "certutil", "bitsadmin", "notepad", "calc", "msbuild", "installutil", "regasm", "regsvcs"
    };

    private sealed class ScanState { public long WindowStart; public readonly HashSet<int> Ports = new(); public long LastAlert = Never; public long Last; }
    private sealed class CountState { public long WindowStart; public int Count; public long LastAlert = Never; public long Last; }
    private sealed class BeaconState { public readonly long[] Times = new long[24]; public int Count; public long LastAlert = Never; public long Last; }
    private sealed class DnsState { public long WindowStart; public readonly HashSet<string> Names = new(); public long LastAlert = Never; public long Last; }
    private sealed class ProcState { public long BucketStart; public long Bytes; public double Mean; public double Var; public int N; public long LastAlert = Never; public long Last; }

    private readonly NotificationService _notify;
    private readonly object _gate = new();

    private readonly Dictionary<string, ScanState> _scan = new();
    private readonly Dictionary<string, CountState> _brute = new();
    private readonly Dictionary<string, long> _exposed = new();
    private readonly Dictionary<string, BeaconState> _beacons = new();
    private readonly Dictionary<string, ProcState> _procs = new();
    private readonly Dictionary<string, long> _lolbinAlerted = new();
    private readonly Dictionary<string, DnsState> _dgaByProc = new();
    private readonly Dictionary<string, DnsState> _tunnels = new();
    private readonly Dictionary<string, bool> _privateCache = new();
    private readonly Dictionary<string, bool> _lolbinCache = new();
    private readonly HashSet<string> _knownProcs = new(StringComparer.OrdinalIgnoreCase);
    private long _learningUntil;
    private bool _knownDirty;

    private HashSet<string>? _listeners;
    private Timer? _timer;
    private bool _running;

    public AnomalyDetectionService(NotificationService notify) => _notify = notify;

    /// <summary>Источник времени в мс (подменяется в тестах).</summary>
    public Func<long> Clock { get; set; } = () => Environment.TickCount64;

    private static DetectionSettings S => SettingsService.Current.Detection;

    public void Start()
    {
        lock (_gate)
        {
            if (_running) return;
            _running = true;
            foreach (var p in SettingsService.Current.KnownProcesses) _knownProcs.Add(p);
            _learningUntil = _knownProcs.Count == 0
                ? Clock() + S.LearningMinutes * 60_000L
                : 0;
            _listeners = null;
            _timer = new Timer(_ => Tick(), null, 1000, 30_000);
        }
    }

    public void Stop()
    {
        Timer? t;
        lock (_gate)
        {
            if (!_running) return;
            _running = false;
            t = _timer;
            _timer = null;
        }
        t?.Dispose();
        SaveKnown();
    }

    public void Dispose() => Stop();

    // ───────────── Поток пакетов ─────────────

    public void Inspect(PacketRecord r)
    {
        if (!_running || !S.Enabled) return;

        long now = Clock();
        bool tcp = r.Protocol == "TCP";
        bool syn = tcp && (r.TcpFlags & 0x12) == 0x02;

        if (r.DnsName is not null)
        {
            lock (_gate) InspectDns(r, now);
            return;
        }

        if (r.Direction == TrafficDirection.Inbound)
        {
            if (syn) lock (_gate) InboundSyn(r, now);
        }
        else if (r.Direction == TrafficDirection.Outbound)
        {
            lock (_gate)
            {
                if (IsPrivate(r.DestinationIp)) return;
                if (_notify.IsWhitelisted(r.DestinationIp)) return;
                if (syn) OutboundConnect(r, now);
                CheckEncryptedDns(r, now);
                TrackBytes(r, now);
                TrackProcess(r, now);
            }
        }
    }

    /// <summary>DNS-запросы: DGA (много «случайных» доменов) и DNS-туннель (много уникальных поддоменов одного домена).</summary>
    private void InspectDns(PacketRecord r, long now) => InspectDnsName(r.DnsName!, r.ProcessName, now);

    /// <summary>Имя из DNS-запроса, полученное вне потока пакетов (ETW DNS-Client).</summary>
    public void InspectDnsQuery(string name, string process)
    {
        if (!_running || !S.Enabled || string.IsNullOrEmpty(name)) return;
        long now = Clock();
        lock (_gate) InspectDnsName(name, process, now);
    }

    private void InspectDnsName(string name, string process, long now)
    {
        var baseDomain = DnsQueryParser.BaseDomain(name, out var sub);

        // DGA: «случайная» метка второго уровня (высокая энтропия, длинная), несколько штук от одного процесса
        if (IsStrong(process))
        {
            int dot = baseDomain.IndexOf('.');
            var label = dot > 0 ? baseDomain[..dot] : baseDomain;
            if (label.Length >= 12 && DnsQueryParser.Entropy(label) >= 3.5)
            {
                if (!_dgaByProc.TryGetValue(process, out var st))
                {
                    if (_dgaByProc.Count >= MaxEntries) _dgaByProc.Clear();
                    _dgaByProc[process] = st = new DnsState { WindowStart = now };
                }
                st.Last = now;
                if (now - st.WindowStart > 60_000) { st.WindowStart = now; st.Names.Clear(); }
                if (st.Names.Count < 64) st.Names.Add(baseDomain);
                if (st.Names.Count >= 5 && now - st.LastAlert > 600_000)
                {
                    st.LastAlert = now;
                    _notify.RaiseExternal(NotificationSeverity.Warning, "Возможный DGA (случайные домены)",
                        $"{process}: {st.Names.Count} доменов с «случайными» именами за минуту, например {st.Names.First()}");
                }
            }
        }

        // DNS-туннель: много разных поддоменов одного домена или очень длинные имена
        if (sub.Length > 0)
        {
            if (!_tunnels.TryGetValue(baseDomain, out var t))
            {
                if (_tunnels.Count >= MaxEntries) _tunnels.Clear();
                _tunnels[baseDomain] = t = new DnsState { WindowStart = now };
            }
            t.Last = now;
            if (now - t.WindowStart > 60_000) { t.WindowStart = now; t.Names.Clear(); }
            if (t.Names.Count < 256) t.Names.Add(sub);
            bool longName = name.Length > 100;
            if ((t.Names.Count >= 50 || longName) && now - t.LastAlert > 600_000)
            {
                t.LastAlert = now;
                _notify.RaiseExternal(NotificationSeverity.Warning, "Подозрение на DNS-туннель",
                    $"{process}: {baseDomain} — {t.Names.Count} уникальных поддоменов за минуту" +
                    (longName ? ", есть очень длинные имена" : string.Empty));
            }
        }
    }

    private void InboundSyn(PacketRecord r, long now)
    {
        string ip = r.SourceIp;
        int port = r.DestinationPort;
        if (ip.Length == 0 || ip == "::1" || ip.StartsWith("127.", StringComparison.Ordinal)) return;
        if (_notify.IsWhitelisted(ip)) return;
        bool external = !IsPrivate(ip);

        // Сканирование портов
        if (!_scan.TryGetValue(ip, out var sc))
        {
            if (_scan.Count >= MaxEntries) _scan.Clear();
            _scan[ip] = sc = new ScanState { WindowStart = now };
        }
        sc.Last = now;
        if (now - sc.WindowStart > S.PortScanWindowSec * 1000L) { sc.WindowStart = now; sc.Ports.Clear(); }
        if (sc.Ports.Count < 512) sc.Ports.Add(port);
        if (sc.Ports.Count >= S.PortScanDistinctPorts && now - sc.LastAlert > 300_000)
        {
            sc.LastAlert = now;
            _notify.RaiseExternal(NotificationSeverity.Critical, "Сканирование портов",
                $"{ip} обратился к {sc.Ports.Count} разным портам за {S.PortScanWindowSec} с" +
                (external ? " (внешний адрес)" : " (локальная сеть)"));
        }

        if (!external) return;

        // Подбор пароля / частые попытки на служебный порт
        if (AuthPorts.Contains(port))
        {
            string key = ip + ":" + port;
            if (!_brute.TryGetValue(key, out var bs))
            {
                if (_brute.Count >= MaxEntries) _brute.Clear();
                _brute[key] = bs = new CountState { WindowStart = now };
            }
            bs.Last = now;
            if (now - bs.WindowStart > S.BruteForceWindowSec * 1000L) { bs.WindowStart = now; bs.Count = 0; }
            if (++bs.Count >= S.BruteForceAttempts && now - bs.LastAlert > 300_000)
            {
                bs.LastAlert = now;
                _notify.RaiseExternal(NotificationSeverity.Critical, "Подозрение на подбор пароля",
                    $"{ip} — {bs.Count} подключений к порту {port} ({PortServiceCatalog.LookupPair("TCP", 0, port)}) за {S.BruteForceWindowSec} с");
            }
        }

        // Внешнее обращение к чувствительному порту
        if (SensitivePorts.Contains(port))
        {
            string key = ip + ":" + port;
            if (!_exposed.TryGetValue(key, out var last) || now - last > 600_000)
            {
                if (_exposed.Count >= MaxEntries) _exposed.Clear();
                _exposed[key] = now;
                _notify.RaiseExternal(
                    CriticalPorts.Contains(port) ? NotificationSeverity.Critical : NotificationSeverity.Warning,
                    "Входящее подключение извне",
                    $"{ip} → порт {port} этого ПК");
            }
            else _exposed[key] = last;
        }
    }

    private void OutboundConnect(PacketRecord r, long now)
    {
        if (!IsStrong(r.ProcessName)) return;
        string key = r.ProcessName + "|" + r.DestinationIp + ":" + r.DestinationPort;
        if (!_beacons.TryGetValue(key, out var b))
        {
            if (_beacons.Count >= MaxEntries) _beacons.Clear();
            _beacons[key] = b = new BeaconState();
        }
        b.Last = now;
        if (b.Count > 0 && now - b.Times[b.Count - 1] < 1000) return; // ретрансмиты SYN

        if (b.Count == b.Times.Length)
        {
            Array.Copy(b.Times, 1, b.Times, 0, b.Times.Length - 1);
            b.Count--;
        }
        b.Times[b.Count++] = now;

        int need = Math.Clamp(S.BeaconMinConnections, 5, b.Times.Length);
        if (b.Count < need || now - b.LastAlert < 3_600_000) return;

        int n = b.Count - 1;
        double sum = 0;
        for (int i = 1; i < b.Count; i++) sum += b.Times[i] - b.Times[i - 1];
        double mean = sum / n;
        if (mean < 5_000 || mean > 3_600_000) return;
        double sq = 0;
        for (int i = 1; i < b.Count; i++)
        {
            double d = (b.Times[i] - b.Times[i - 1]) - mean;
            sq += d * d;
        }
        double cv = Math.Sqrt(sq / n) / mean;
        if (cv < S.BeaconMaxVariation)
        {
            b.LastAlert = now;
            _notify.RaiseExternal(NotificationSeverity.Warning, "Периодические подключения (beaconing)",
                $"{r.ProcessName} → {r.DestinationIp}:{r.DestinationPort}: {b.Count} подключений с интервалом ≈{mean / 1000:F0} с (разброс {cv:P0}). " +
                "Может быть легитимным (обновления, синхронизация) — добавьте в белый список, если это так.");
        }
    }

    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "yandex", "browser", "thorium", "chromium",
        "iexplore", "waterfox", "librewolf", "tor", "arc", "dnscache"
    };

    private static readonly string[] DohProviders =
    {
        "dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "dns.adguard.com",
        "dns.adguard-dns.com", "doh.opendns.com", "dns.nextdns.io", "doh.dns.sb", "dns.alidns.com", "doh.pub",
        "dns.mullvad.net", "doh.cleanbrowsing.org", "dns.controld.com", "freedns.controld.com"
    };

    private readonly Dictionary<string, long> _encDnsAlerted = new();

    /// <summary>
    /// DoT (порт 853) или DoH к известному провайдеру (по SNI) от процесса, не являющегося браузером:
    /// так прячут DNS-запросы от системного резолвера и мониторинга. Содержимое запросов не читается.
    /// </summary>
    private void CheckEncryptedDns(PacketRecord r, long now)
    {
        string? kind = null, target = null;
        if (r.DestinationPort == 853 && r.Protocol == "TCP") { kind = "DoT"; target = r.DestinationIp + ":853"; }
        else if (!string.IsNullOrEmpty(r.Sni))
        {
            foreach (var p in DohProviders)
            {
                if (r.Sni.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                    r.Sni.EndsWith("." + p, StringComparison.OrdinalIgnoreCase))
                {
                    kind = "DoH"; target = r.Sni; break;
                }
            }
        }
        if (kind is null || !IsStrong(r.ProcessName)) return;

        var proc = r.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? r.ProcessName[..^4] : r.ProcessName;
        if (Browsers.Contains(proc)) return;

        string key = r.ProcessName + "|" + target;
        if (_encDnsAlerted.TryGetValue(key, out var last) && now - last < 3_600_000) return;
        if (_encDnsAlerted.Count >= MaxEntries) _encDnsAlerted.Clear();
        _encDnsAlerted[key] = now;
        _notify.RaiseExternal(NotificationSeverity.Warning, "Шифрованный DNS в обход системы",
            $"{r.ProcessName} использует {kind} ({target}) — запросы не видны системному резолверу. " +
            "Для браузеров это норма, для остальных программ подозрительно.");
    }

    private void TrackBytes(PacketRecord r, long now)
    {
        string name = string.IsNullOrEmpty(r.ProcessName) ? "unknown" : r.ProcessName;
        if (!_procs.TryGetValue(name, out var p))
        {
            if (_procs.Count >= MaxEntries) _procs.Clear();
            _procs[name] = p = new ProcState { BucketStart = now };
        }
        p.Last = now;
        long elapsed = now - p.BucketStart;
        if (elapsed >= BucketMs)
        {
            Evaluate(name, p, now);
            Update(p, p.Bytes);
            int gaps = (int)Math.Min(elapsed / BucketMs - 1, 12);
            for (int i = 0; i < gaps; i++) Update(p, 0);
            p.Bytes = 0;
            p.BucketStart = now;
        }
        p.Bytes += r.Size;
    }

    private static void Update(ProcState p, long bytes)
    {
        const double alpha = 0.05;
        p.N++;
        if (p.N == 1) { p.Mean = bytes; p.Var = 0; return; }
        double diff = bytes - p.Mean;
        p.Mean += alpha * diff;
        p.Var = (1 - alpha) * (p.Var + alpha * diff * diff);
    }

    private void Evaluate(string name, ProcState p, long now)
    {
        if (p.N < WarmupBuckets || p.Bytes < S.ExfilMinBytes) return;
        if (p.Bytes <= p.Mean * 3 || p.Bytes <= p.Mean + S.ExfilSigma * Math.Sqrt(p.Var)) return;
        if (now - p.LastAlert < 600_000) return;
        p.LastAlert = now;
        _notify.RaiseExternal(NotificationSeverity.Warning, "Всплеск исходящего трафика",
            $"{name}: {ByteFormatter.Format(p.Bytes)} за {BucketMs / 1000} с наружу (обычно ≈{ByteFormatter.Format((long)p.Mean)})");
    }

    private void TrackProcess(PacketRecord r, long now)
    {
        string name = r.ProcessName;
        if (!IsStrong(name)) return;

        if (IsLolbin(name))
        {
            string key = name + "|" + r.DestinationIp;
            if (!_lolbinAlerted.TryGetValue(key, out var last) || now - last > 3_600_000)
            {
                if (_lolbinAlerted.Count >= MaxEntries) _lolbinAlerted.Clear();
                _lolbinAlerted[key] = now;
                _notify.RaiseExternal(NotificationSeverity.Warning, "Системная утилита выходит в сеть",
                    $"{name} → {r.DestinationIp}:{r.DestinationPort}");
            }
        }

        if (_knownProcs.Add(name))
        {
            _knownDirty = true;
            if (now >= _learningUntil)
                _notify.RaiseExternal(NotificationSeverity.Info, "Новый процесс в сети",
                    $"{name} впервые вышел в сеть: {r.DestinationIp}:{r.DestinationPort}");
        }
    }

    private bool IsLolbin(string name)
    {
        if (_lolbinCache.TryGetValue(name, out var v)) return v;
        var n = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        v = Lolbins.Contains(n);
        if (_lolbinCache.Count < 4096) _lolbinCache[name] = v;
        return v;
    }

    private bool IsPrivate(string ip)
    {
        if (_privateCache.TryGetValue(ip, out var v)) return v;
        v = NotificationService.IsLocalOrPrivate(ip);
        if (_privateCache.Count >= 50_000) _privateCache.Clear();
        _privateCache[ip] = v;
        return v;
    }

    private static bool IsStrong(string? name) =>
        !string.IsNullOrEmpty(name) && name != "unknown" && name[0] != '~' && name != "system" && name != "System";

    // ───────────── Таймер: слушающие порты, очистка, сохранение базы ─────────────

    private void Tick()
    {
        try { CheckListeners(); } catch { }
        try { Sweep(); } catch { }
        try { SaveKnown(); } catch { }
    }

    private void CheckListeners()
    {
        var current = new HashSet<string>();
        foreach (var ep in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())
        {
            if (System.Net.IPAddress.IsLoopback(ep.Address)) continue;
            current.Add(ep.Address + ":" + ep.Port);
        }

        List<string>? added = null;
        lock (_gate)
        {
            if (_listeners is null) { _listeners = current; return; } // первый снимок — база, без тревог
            foreach (var l in current)
                if (!_listeners.Contains(l)) (added ??= new()).Add(l);
            _listeners = current;
        }
        if (added is null || !S.Enabled) return;
        foreach (var l in added.Take(5))
            _notify.RaiseExternal(NotificationSeverity.Warning, "Новый слушающий порт",
                $"Приложение открыло порт для входящих подключений: {l}");
        if (added.Count > 5)
            _notify.RaiseExternal(NotificationSeverity.Warning, "Новые слушающие порты", $"…и ещё {added.Count - 5}");
    }

    private void Sweep()
    {
        long now = Clock();
        lock (_gate)
        {
            SweepDict(_scan, s => s.Last, now, 900_000);
            SweepDict(_brute, s => s.Last, now, 900_000);
            SweepDict(_beacons, s => s.Last, now, 7_200_000);
            SweepDict(_procs, s => s.Last, now, 3_600_000);
            SweepDict(_exposed, v => v, now, 900_000);
            SweepDict(_lolbinAlerted, v => v, now, 7_200_000);
            SweepDict(_encDnsAlerted, v => v, now, 7_200_000);
            SweepDict(_dgaByProc, s => s.Last, now, 900_000);
            SweepDict(_tunnels, s => s.Last, now, 900_000);
        }
    }

    private static void SweepDict<T>(Dictionary<string, T> d, Func<T, long> last, long now, long ttl)
    {
        if (d.Count == 0) return;
        List<string>? remove = null;
        foreach (var kv in d)
            if (now - last(kv.Value) > ttl) (remove ??= new()).Add(kv.Key);
        if (remove is not null) foreach (var k in remove) d.Remove(k);
    }

    private void SaveKnown()
    {
        List<string>? snapshot = null;
        lock (_gate)
        {
            if (_knownDirty)
            {
                _knownDirty = false;
                snapshot = _knownProcs.ToList();
            }
        }
        if (snapshot is null) return;
        SettingsService.Current.KnownProcesses = snapshot;
        SettingsService.Save();
    }
}
