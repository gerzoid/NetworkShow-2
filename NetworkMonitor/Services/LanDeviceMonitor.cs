using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

/// <summary>
/// Инвентаризация устройств локальной сети по таблице ARP (опрос раз в 15 с + активное сканирование подсети по кнопке):
///  • новое (не доверенное) устройство → предупреждение; первые N минут после первого запуска — «обучение» без тревог;
///  • один и тот же IP внезапно у другого MAC (конфликт IP / ARP-подмена) → предупреждение, для шлюза — критично.
/// Видит только соседей, с которыми ПК общался (или которых нашло сканирование); доверенные MAC хранятся в настройках.
/// </summary>
public sealed class LanDeviceMonitor : IDisposable
{
    private readonly NotificationService _notify;
    private readonly object _lock = new();
    private readonly Dictionary<string, LanDevice> _devices = new();
    private readonly Dictionary<string, (string Mac, long Time)> _ipMac = new();
    private readonly Dictionary<string, long> _alerted = new();
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _gateways = new();
    private long _learningUntil;
    private bool _knownDirty;
    private Timer? _timer;

    /// <summary>Источник записей ARP (подменяется в тестах).</summary>
    public Func<IReadOnlyList<ArpEntry>> Source { get; set; } = () => ArpNative.Read();
    public Func<long> Clock { get; set; } = () => Environment.TickCount64;

    public event Action<IReadOnlyList<LanDevice>>? Updated;

    public LanDeviceMonitor(NotificationService notify) => _notify = notify;

    private static DetectionSettings S => SettingsService.Current.Detection;

    public void Start(bool autoPoll = true)
    {
        lock (_lock)
        {
            if (_timer is not null) return;
            _known.Clear();
            foreach (var k in SettingsService.Current.KnownDevices) _known.Add(k.Mac);
            _learningUntil = _known.Count == 0 ? Clock() + S.LearningMinutes * 60_000L : 0;
        }
        if (autoPoll) _timer = new Timer(_ => SafePoll(), null, 500, 15_000);
        else _timer = new Timer(_ => { }, null, Timeout.Infinite, Timeout.Infinite);
    }

    public void Stop()
    {
        var t = _timer;
        _timer = null;
        t?.Dispose();
        SaveKnown();
    }

    public void Dispose() => Stop();

    public IReadOnlyList<LanDevice> Snapshot()
    {
        lock (_lock) return _devices.Values.ToList();
    }

    // ───────────── Определение устройства ─────────────

    private readonly Dictionary<string, List<DeviceHint>> _pendingHints = new();

    /// <summary>Признак устройства из служебного трафика (DHCP, mDNS, SSDP); вызывается потоком захвата.</summary>
    public void AddHint(DeviceHint h)
    {
        lock (_lock)
        {
            LanDevice? d = null;
            if (h.Mac is not null) _devices.TryGetValue(h.Mac, out d);
            d ??= _devices.Values.FirstOrDefault(x => x.Ip == h.Ip);
            if (d is null)
            {
                if (h.Ip == "0.0.0.0" && h.Mac is null) return;
                if (_pendingHints.Count > 200) _pendingHints.Clear();
                var key = h.Mac ?? h.Ip;
                if (!_pendingHints.TryGetValue(key, out var list)) _pendingHints[key] = list = new List<DeviceHint>();
                if (list.Count < 16) list.Add(h);
                return;
            }
            ApplyHint(d, h);
            Reclassify(d);
        }
    }

    private void ApplyHint(LanDevice d, DeviceHint h)
    {
        (string label, int priority) = h.Kind switch
        {
            "hostname" => ("DHCP-имя", 4),
            "dhcp-vendor" => ("DHCP", 0),
            "mdns-host" => ("mDNS-имя", 3),
            "name" => ("mDNS", 2),
            "service" => ("служба", 0),
            "model" => ("модель", 0),
            "ssdp-server" => ("SSDP", 0),
            _ => ("UPnP", 0)
        };
        if (d.HintSet.Count < 14) d.HintSet.Add($"{label}: {h.Text}");
        if (priority > 0 && priority >= d.NamePriority && !string.IsNullOrWhiteSpace(h.Text))
        {
            d.Name = h.Text;
            d.NamePriority = priority;
        }
    }

    private void Reclassify(LanDevice d)
    {
        d.Vendor = OuiDatabase.Lookup(d.Mac);
        d.DeviceType = DeviceClassifier.Guess(d.Vendor, d.Name, d.HintSet.Select(x => x), d.IsGateway, d.IsRandomMac);
        d.HintsText = string.Join("; ", d.HintSet.Take(6));
    }

    /// <summary>Доверие и описание устройства по IP (для детектора подключений из LAN): null — устройство ещё не известно.</summary>
    public (bool? Trusted, string Label) LookupByIp(string ip)
    {
        lock (_lock)
        {
            var d = _devices.Values.FirstOrDefault(x => x.Ip == ip);
            if (d is null) return (null, string.Empty);
            var label = string.Join(" · ", new[] { d.Name, d.Vendor, d.DeviceType }.Where(x => !string.IsNullOrEmpty(x)));
            return (d.IsKnown, label);
        }
    }

    private void SafePoll() { try { Poll(); } catch { } }

    public void Poll()
    {
        var entries = Source();
        long now = Clock();
        var seen = new HashSet<string>();
        var created = new List<LanDevice>();
        var alerts = new List<(NotificationSeverity, string, string)>();

        lock (_lock)
        {
            _gateways = ReadGateways();
            foreach (var e in entries)
            {
                if (!IsUsable(e)) continue;
                seen.Add(e.Mac);

                if (!_devices.TryGetValue(e.Mac, out var d))
                {
                    d = new LanDevice { Mac = e.Mac, FirstSeen = DateTime.Now, Ip = e.Ip, IsKnown = _known.Contains(e.Mac) };
                    _devices[e.Mac] = d;
                    created.Add(d);
                    d.IsGateway = _gateways.Contains(e.Ip);
                    ApplyPending(d);
                    Reclassify(d);
                    if (!d.IsKnown)
                    {
                        if (now < _learningUntil) TrustLocked(d);
                        else alerts.Add((NotificationSeverity.Warning, "Новое устройство в сети",
                            $"{e.Ip} · MAC {e.Mac} · {(d.Vendor.Length > 0 ? d.Vendor : d.MacKind)}, {d.DeviceType}. Если это ваше устройство — отметьте его как доверенное на вкладке «Устройства (ARP)»."));
                    }
                }
                d.Ip = e.Ip;
                d.LastSeen = DateTime.Now;
                d.IsOnline = true;
                bool gw = _gateways.Contains(e.Ip);
                if (gw != d.IsGateway) { d.IsGateway = gw; Reclassify(d); }

                // Тот же IP у другого MAC за короткое время — конфликт адресов или подмена ARP
                if (_ipMac.TryGetValue(e.Ip, out var prev) && !prev.Mac.Equals(e.Mac, StringComparison.OrdinalIgnoreCase) && now - prev.Time < 300_000)
                {
                    string key = e.Ip + "|" + prev.Mac + "|" + e.Mac;
                    if (!_alerted.TryGetValue(key, out var last) || now - last > 600_000)
                    {
                        if (_alerted.Count > 2000) _alerted.Clear();
                        _alerted[key] = now;
                        alerts.Add((gw ? NotificationSeverity.Critical : NotificationSeverity.Warning,
                            gw ? "Возможная ARP-подмена шлюза" : "Конфликт IP-адреса в сети",
                            $"{e.Ip} раньше отвечал с MAC {prev.Mac}, теперь с {e.Mac}" +
                            (gw ? " — так перехватывают трафик (man-in-the-middle). Проверьте роутер и устройства." : ".")));
                    }
                }
                _ipMac[e.Ip] = (e.Mac, now);
            }

            var offlineCutoff = DateTime.Now.AddMinutes(-2);
            foreach (var d in _devices.Values)
                if (!seen.Contains(d.Mac) && d.LastSeen < offlineCutoff) d.IsOnline = false;
        }

        if (S.Enabled)
            foreach (var (sev, title, msg) in alerts) _notify.RaiseExternal(sev, title, msg);
        foreach (var d in created) _ = ResolveNameAsync(d);
        Updated?.Invoke(Snapshot());
    }

    // ───────────── Доверие ─────────────

    public void Trust(string mac)
    {
        lock (_lock)
        {
            if (_devices.TryGetValue(mac, out var d)) TrustLocked(d);
        }
        SaveKnown();
        Updated?.Invoke(Snapshot());
    }

    public void TrustAll()
    {
        lock (_lock)
            foreach (var d in _devices.Values) if (!d.IsKnown) TrustLocked(d);
        SaveKnown();
        Updated?.Invoke(Snapshot());
    }

    private void TrustLocked(LanDevice d)
    {
        d.IsKnown = true;
        if (_known.Add(d.Mac)) _knownDirty = true;
    }

    private void SaveKnown()
    {
        List<KnownDevice>? list = null;
        lock (_lock)
        {
            if (!_knownDirty) return;
            _knownDirty = false;
            list = _devices.Values.Where(d => d.IsKnown)
                .Select(d => new KnownDevice { Mac = d.Mac, Name = d.Name, FirstSeen = d.FirstSeen }).ToList();
            foreach (var mac in _known)
                if (list.All(k => k.Mac != mac)) list.Add(new KnownDevice { Mac = mac, FirstSeen = DateTime.Now });
        }
        SettingsService.Current.KnownDevices = list;
        SettingsService.Save();
    }

    // ───────────── Активное сканирование ─────────────

    /// <summary>ARP-запрос ко всем адресам локальных подсетей (до 1022 хостов на подсеть); возвращает число ответивших.</summary>
    public async Task<int> ScanAsync(CancellationToken ct = default)
    {
        var targets = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up ||
                    nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask is null) continue;
                    if (IpClassifier.Classify(ua.Address) != IpScope.Private) continue;
                    targets.AddRange(HostsOf(ua.Address, ua.IPv4Mask));
                }
            }
        }
        catch { }

        int found = 0;
        await Parallel.ForEachAsync(targets.Distinct(), new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = ct },
            (ip, _) =>
            {
                if (ArpNative.Resolve(ip) is not null) Interlocked.Increment(ref found);
                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);

        Poll();
        return found;
    }

    /// <summary>Адреса хостов подсети (без сетевого, broadcast и собственного); пусто, если подсеть шире /22.</summary>
    public static IEnumerable<IPAddress> HostsOf(IPAddress addr, IPAddress mask)
    {
        var a = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(addr.GetAddressBytes());
        var m = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
        uint net = a & m, bc = net | ~m;
        long hosts = (long)bc - net - 1;
        if (hosts < 1 || hosts > 1022) yield break;
        for (uint x = net + 1; x < bc; x++)
        {
            if (x == a) continue;
            var bytes = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, x);
            yield return new IPAddress(bytes);
        }
    }

    // ───────────── Вспомогательное ─────────────

    private static bool IsUsable(ArpEntry e)
    {
        if (e.Mac.Length != 17 || e.Mac.Equals("FF-FF-FF-FF-FF-FF", StringComparison.OrdinalIgnoreCase) || e.Mac.Equals("00-00-00-00-00-00")) return false;
        // Групповой MAC (multicast): младший бит первого октета
        if (int.TryParse(e.Mac.AsSpan(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var first) && (first & 1) != 0) return false;
        var scope = IpClassifier.Classify(e.Ip);
        return scope is IpScope.Private or IpScope.LinkLocal;
    }

    private static HashSet<string> ReadGateways()
    {
        var set = new HashSet<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var g in nic.GetIPProperties().GatewayAddresses)
                    if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                        set.Add(g.Address.ToString());
            }
        }
        catch { }
        return set;
    }

    private void ApplyPending(LanDevice d)
    {
        foreach (var key in new[] { d.Mac, d.Ip })
        {
            if (!_pendingHints.Remove(key, out var list)) continue;
            foreach (var h in list) ApplyHint(d, h);
        }
    }

    private async Task ResolveNameAsync(LanDevice d)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var host = await Dns.GetHostEntryAsync(d.Ip, cts.Token).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(host.HostName) && host.HostName != d.Ip && string.IsNullOrEmpty(d.Name))
            {
                lock (_lock)
                {
                    d.Name = host.HostName;
                    Reclassify(d);
                }
            }
        }
        catch { }
    }
}
