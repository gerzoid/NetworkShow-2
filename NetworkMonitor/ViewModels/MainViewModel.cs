using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using SkiaSharp;

namespace NetworkMonitor.ViewModels;

public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly ProcessResolverService _processResolver;
    private readonly EtwConnectionTracker _etwTracker;
    private readonly PacketCaptureService _captureService;
    private readonly AggregationService _aggregation;
    private readonly NotificationService _notifications;
    private readonly LoggingService _logging;
    private readonly DnsResolverService _dns;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _uiTimer;
    private readonly Timer _pruneTimer;
    private CancellationTokenSource? _consumerCts;
    private Task? _consumerTask;

    private static readonly TimeSpan ConnectionInactivityTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromSeconds(30);

    private readonly HashSet<string> _connectionKeys = new();
    private readonly Dictionary<string, List<ConnectionAggregate>> _byRemoteIp = new();
    private readonly Dictionary<string, RemoteIpAggregate> _ipIndex = new();
    private readonly ObservableCollection<TrafficNotification> _notificationItems = new();
    private readonly EventHandler<Themes.AppTheme> _themeChangedHandler;
    private int _inactivityRefreshCounter;
    // Инкремент при Clear(): отложенные BeginInvoke со старым поколением пропускаются,
    // иначе в таблицу попадают строки, которых уже нет в агрегации
    private int _clearGeneration;
    private long _lastUiTickTimestamp;

    /// <summary>Окно скрыто в трее — тяжёлые обновления UI (график, топы, Refresh) не нужны.</summary>
    public bool UiUpdatesSuspended { get; set; }

    public ObservableCollection<ConnectionAggregate> Connections { get; } = new();
    public ICollectionView ConnectionsView { get; }
    public ObservableCollection<RemoteIpAggregate> RemoteIps { get; } = new();
    public ICollectionView RemoteIpsView { get; }
    public ObservableCollection<TrafficNotification> Notifications => _notificationItems;
    public ObservableCollection<NetworkInterfaceInfo> Interfaces { get; } = new();
    public ObservableCollection<TopEntry> TopIps { get; } = new();
    public ObservableCollection<TopEntry> TopProcesses { get; } = new();

    public string[] ProtocolOptions { get; } = { "All", "TCP", "UDP" };
    public string[] ScopeOptions { get; } = { "Все", "Только локальный", "Только внешний" };
    public string[] GroupingOptions { get; } = { "Без группировки", "По процессу", "По удалённому хосту", "По протоколу", "По зоне" };
    public LogFormat[] LogFormatOptions { get; } = { LogFormat.Json, LogFormat.Csv };

    [ObservableProperty]
    private NetworkInterfaceInfo? selectedInterface;

    [ObservableProperty]
    private bool isCapturing;

    [ObservableProperty]
    private bool isPaused;

    [ObservableProperty]
    private long totalPackets;

    [ObservableProperty]
    private string totalBytesInText = "0 B";

    [ObservableProperty]
    private string totalBytesOutText = "0 B";

    [ObservableProperty]
    private string speedInText = "0 B/s";

    [ObservableProperty]
    private string speedOutText = "0 B/s";

    [ObservableProperty]
    private string statusText = "Готов. Запустите захват, выбрав интерфейс.";

    [ObservableProperty]
    private string searchText = string.Empty;

    [ObservableProperty]
    private string ipFilter = string.Empty;

    [ObservableProperty]
    private string ipRangeFrom = string.Empty;

    [ObservableProperty]
    private string ipRangeTo = string.Empty;

    [ObservableProperty]
    private string processFilter = string.Empty;

    [ObservableProperty]
    private string protocolFilter = "All";

    [ObservableProperty]
    private bool hideUnknownProcess;

    [ObservableProperty]
    private string scopeFilter = "Все";

    [ObservableProperty]
    private string selectedGrouping = "Без группировки";

    [ObservableProperty]
    private bool logToFile;

    [ObservableProperty]
    private LogFormat logFormat = LogFormat.Json;

    [ObservableProperty]
    private long droppedPackets;

    [ObservableProperty]
    private int connectionCount;

    public ObservableCollection<ISeries> SpeedSeries { get; }
    public ObservableCollection<Axis> SpeedXAxes { get; }
    public ObservableCollection<Axis> SpeedYAxes { get; }

    private readonly ObservableCollection<DateTimePoint> _speedInPoints = new();
    private readonly ObservableCollection<DateTimePoint> _speedOutPoints = new();

    public MainViewModel()
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        _processResolver = new ProcessResolverService();
        _etwTracker = new EtwConnectionTracker(_processResolver);
        _captureService = new PacketCaptureService(_processResolver);
        _aggregation = new AggregationService();
        _notifications = new NotificationService();
        _logging = new LoggingService();
        _dns = new DnsResolverService();

        _captureService.CaptureError += (_, msg) => _dispatcher.BeginInvoke(() => StatusText = msg);
        _notifications.NotificationRaised += OnNotificationRaised;
        _aggregation.ConnectionCreated += OnConnectionCreated;
        _aggregation.RemoteIpCreated += OnRemoteIpCreated;
        _aggregation.ConnectionsPruned += OnConnectionsPruned;
        _aggregation.RemoteIpsPruned += OnRemoteIpsPruned;
        _dns.Resolved += OnDnsResolved;

        ConnectionsView = CollectionViewSource.GetDefaultView(Connections);
        ConnectionsView.Filter = FilterConnection;
        ConnectionsView.SortDescriptions.Add(new SortDescription(nameof(ConnectionAggregate.LastSeen), ListSortDirection.Descending));

        RemoteIpsView = CollectionViewSource.GetDefaultView(RemoteIps);
        RemoteIpsView.SortDescriptions.Add(new SortDescription(nameof(RemoteIpAggregate.Bytes), ListSortDirection.Descending));

        SpeedSeries = new ObservableCollection<ISeries>
        {
            new LineSeries<DateTimePoint>
            {
                Name = "Входящий",
                Values = _speedInPoints,
                Fill = new SolidColorPaint(new SKColor(40, 120, 200, 80)),
                Stroke = new SolidColorPaint(new SKColor(40, 140, 230)) { StrokeThickness = 2 },
                GeometrySize = 0
            },
            new LineSeries<DateTimePoint>
            {
                Name = "Исходящий",
                Values = _speedOutPoints,
                Fill = new SolidColorPaint(new SKColor(220, 100, 80, 80)),
                Stroke = new SolidColorPaint(new SKColor(230, 110, 90)) { StrokeThickness = 2 },
                GeometrySize = 0
            }
        };
        SpeedXAxes = new ObservableCollection<Axis>
        {
            new Axis
            {
                Labeler = v => new DateTime((long)v).ToString("HH:mm:ss"),
                LabelsPaint = new SolidColorPaint(SKColors.LightGray),
                SeparatorsPaint = new SolidColorPaint(new SKColor(80, 80, 80))
            }
        };
        SpeedYAxes = new ObservableCollection<Axis>
        {
            new Axis
            {
                Labeler = v => ByteFormatter.FormatRate((long)v),
                LabelsPaint = new SolidColorPaint(SKColors.LightGray),
                SeparatorsPaint = new SolidColorPaint(new SKColor(80, 80, 80))
            }
        };

        ApplyChartTheme(Themes.ThemeManager.Current);
        _themeChangedHandler = (_, t) => _dispatcher.BeginInvoke(() => ApplyChartTheme(t));
        Themes.ThemeManager.ThemeChanged += _themeChangedHandler;

        ApplySavedSettings();
        LoadInterfaces();

        if (_etwTracker.TryStart())
            StatusText = "Готов. ETW активен — PID-резолв в реальном времени.";
        else
            StatusText = $"Готов. ETW недоступен ({_etwTracker.LastError ?? "нет прав?"}) — резолв через таблицы сокетов.";

        _uiTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _uiTimer.Tick += UiTick;
        _uiTimer.Start();

        _pruneTimer = new Timer(_ =>
        {
            _aggregation.Prune(ConnectionInactivityTimeout);
            _dns.Prune();
            _notifications.Prune(TimeSpan.FromHours(24));
        }, null, PruneInterval, PruneInterval);
    }

    private void ApplySavedSettings()
    {
        var s = SettingsService.Current;
        foreach (var entry in s.Blacklist) _notifications.AddToBlacklist(entry);
        foreach (var entry in s.Whitelist) _notifications.AddToWhitelist(entry);
        LogToFile = s.LogToFile;
        if (Enum.TryParse<LogFormat>(s.LogFormat, out var fmt) && LogFormatOptions.Contains(fmt))
            LogFormat = fmt;
        if (ProtocolOptions.Contains(s.ProtocolFilter)) ProtocolFilter = s.ProtocolFilter;
        if (ScopeOptions.Contains(s.ScopeFilter)) ScopeFilter = s.ScopeFilter;
        if (GroupingOptions.Contains(s.Grouping)) SelectedGrouping = s.Grouping;
        HideUnknownProcess = s.HideUnknownProcess;
    }

    public void LoadInterfaces()
    {
        var preferred = SelectedInterface?.Name ?? SettingsService.Current.InterfaceName;
        Interfaces.Clear();
        foreach (var i in _captureService.ListInterfaces())
            Interfaces.Add(i);
        SelectedInterface = Interfaces.FirstOrDefault(i => i.Name == preferred) ?? Interfaces.FirstOrDefault();
        if (Interfaces.Count == 0)
            StatusText = "Сетевые интерфейсы не найдены. Установите Npcap (https://npcap.com).";
    }

    [RelayCommand]
    private void RefreshInterfaces()
    {
        LoadInterfaces();
        StatusText = $"Список интерфейсов обновлён ({Interfaces.Count}).";
    }

    [RelayCommand]
    private void Start()
    {
        if (IsCapturing) return;
        if (SelectedInterface is null)
        {
            StatusText = "Сначала выберите сетевой интерфейс.";
            return;
        }
        try
        {
            _captureService.Start(SelectedInterface.Name);
            IsCapturing = true;
            IsPaused = false;
            StatusText = $"Захват запущен: {SelectedInterface}";

            _consumerCts = new CancellationTokenSource();
            _consumerTask = Task.Run(() => ConsumeLoop(_consumerCts.Token));
        }
        catch (Exception ex)
        {
            StatusText = $"Ошибка запуска захвата: {ex.Message}";
        }
    }

    [RelayCommand]
    private void Stop()
    {
        if (!IsCapturing) return;
        try
        {
            _captureService.Stop();
            _consumerCts?.Cancel();
            _consumerTask?.Wait(500);
        }
        catch { }
        finally
        {
            _consumerCts?.Dispose();
            _consumerCts = null;
            IsCapturing = false;
            IsPaused = false;
            _logging.Flush();
            StatusText = "Захват остановлен.";
        }
    }

    [RelayCommand]
    private void TogglePause()
    {
        if (!IsCapturing) return;
        if (IsPaused)
        {
            if (SelectedInterface is null)
            {
                StatusText = "Не выбран интерфейс для возобновления.";
                return;
            }
            try
            {
                _captureService.Start(SelectedInterface.Name);
                IsPaused = false;
                StatusText = "Захват.";
            }
            catch (Exception ex)
            {
                StatusText = $"Ошибка возобновления захвата: {ex.Message}";
            }
        }
        else
        {
            // Останавливаем сам захват: пакеты за время паузы не считаются,
            // но и не выбрасываются молча при работающем драйвере
            _captureService.Stop();
            IsPaused = true;
            StatusText = "Пауза — захват приостановлен.";
        }
    }

    [RelayCommand]
    private void Clear()
    {
        Interlocked.Increment(ref _clearGeneration);
        Connections.Clear();
        RemoteIps.Clear();
        _ipIndex.Clear();
        _connectionKeys.Clear();
        _byRemoteIp.Clear();
        TopIps.Clear();
        TopProcesses.Clear();
        _speedInPoints.Clear();
        _speedOutPoints.Clear();
        _aggregation.Clear();
        TotalPackets = 0;
        ConnectionCount = 0;
        TotalBytesInText = "0 B";
        TotalBytesOutText = "0 B";
    }

    [RelayCommand]
    private async Task Export()
    {
        try
        {
            var format = LogFormat;
            var path = await Task.Run(() =>
            {
                var snapshot = _aggregation.Connections.OrderByDescending(c => c.Bytes).ToList();
                return _logging.ExportConnections(snapshot, format);
            });
            StatusText = $"Экспортировано: {path}";
        }
        catch (Exception ex)
        {
            StatusText = $"Ошибка экспорта: {ex.Message}";
        }
    }

    [RelayCommand]
    private void RefreshFilter() => ConnectionsView.Refresh();

    [RelayCommand]
    private void ToggleTheme() => Themes.ThemeManager.Toggle();

    [RelayCommand]
    private void AddBlacklist() => AddIpToBlacklist(IpFilter);

    [RelayCommand]
    private void AddWhitelist() => AddIpToWhitelist(IpFilter);

    public void AddIpToBlacklist(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return;
        entry = entry.Trim();
        _notifications.AddToBlacklist(entry);
        var list = SettingsService.Current.Blacklist;
        if (!list.Contains(entry, StringComparer.OrdinalIgnoreCase)) list.Add(entry);
        SettingsService.Save();
        StatusText = $"Добавлено в чёрный список: {entry}";
    }

    public void AddIpToWhitelist(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return;
        entry = entry.Trim();
        _notifications.AddToWhitelist(entry);
        var list = SettingsService.Current.Whitelist;
        if (!list.Contains(entry, StringComparer.OrdinalIgnoreCase)) list.Add(entry);
        SettingsService.Save();
        StatusText = $"Добавлено в белый список: {entry}";
    }

    private async Task ConsumeLoop(CancellationToken token)
    {
        var reader = _captureService.Reader;
        try
        {
            while (await reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var rec))
                {
                    _aggregation.Add(rec);
                    _notifications.Inspect(rec);
                    if (LogToFile)
                    {
                        try { _logging.Format = LogFormat; _logging.Write(rec); }
                        catch { }
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            await _dispatcher.BeginInvoke(() => StatusText = $"Ошибка обработки: {ex.Message}");
        }
    }

    private void OnConnectionCreated(object? sender, ConnectionAggregate conn)
    {
        var cached = _dns.Lookup(conn.RemoteIp);
        if (cached is not null)
        {
            conn.RemoteHost = cached;
        }
        else
        {
            _dns.Enqueue(conn.RemoteIp);
        }

        var generation = Volatile.Read(ref _clearGeneration);
        _dispatcher.BeginInvoke(() =>
        {
            if (generation != Volatile.Read(ref _clearGeneration)) return;
            if (_connectionKeys.Add(conn.Key))
            {
                Connections.Add(conn);
                if (!_byRemoteIp.TryGetValue(conn.RemoteIp, out var list))
                {
                    list = new List<ConnectionAggregate>();
                    _byRemoteIp[conn.RemoteIp] = list;
                }
                list.Add(conn);
            }
        });
    }

    private void OnRemoteIpCreated(object? sender, RemoteIpAggregate ip)
    {
        var cached = _dns.Lookup(ip.Ip);
        if (cached is not null) ip.RemoteHost = cached;
        else _dns.Enqueue(ip.Ip);

        var generation = Volatile.Read(ref _clearGeneration);
        _dispatcher.BeginInvoke(() =>
        {
            if (generation != Volatile.Read(ref _clearGeneration)) return;
            if (_ipIndex.TryAdd(ip.Ip, ip))
                RemoteIps.Add(ip);
        });
    }

    private void OnConnectionsPruned(object? sender, IReadOnlyList<ConnectionAggregate> removed)
    {
        _dispatcher.BeginInvoke(() =>
        {
            var keys = new HashSet<string>(removed.Count);
            foreach (var c in removed) keys.Add(c.Key);

            for (int i = Connections.Count - 1; i >= 0; i--)
            {
                var c = Connections[i];
                if (!keys.Contains(c.Key)) continue;
                Connections.RemoveAt(i);
                _connectionKeys.Remove(c.Key);
                if (_byRemoteIp.TryGetValue(c.RemoteIp, out var list))
                {
                    list.Remove(c);
                    if (list.Count == 0) _byRemoteIp.Remove(c.RemoteIp);
                }
            }
        });
    }

    private void OnRemoteIpsPruned(object? sender, IReadOnlyList<RemoteIpAggregate> removed)
    {
        _dispatcher.BeginInvoke(() =>
        {
            var ips = new HashSet<string>(removed.Count);
            foreach (var ip in removed) ips.Add(ip.Ip);

            for (int i = RemoteIps.Count - 1; i >= 0; i--)
            {
                var ip = RemoteIps[i];
                if (!ips.Contains(ip.Ip)) continue;
                RemoteIps.RemoveAt(i);
                _ipIndex.Remove(ip.Ip);
            }
        });
    }

    private void OnDnsResolved(object? sender, DnsResolvedEventArgs e)
    {
        _dispatcher.BeginInvoke(() =>
        {
            if (_byRemoteIp.TryGetValue(e.Ip, out var list))
            {
                foreach (var c in list)
                    c.RemoteHost = e.Host;
            }
            if (_ipIndex.TryGetValue(e.Ip, out var ipAgg))
                ipAgg.RemoteHost = e.Host;
        });
    }

    private void OnNotificationRaised(object? sender, TrafficNotification n)
    {
        _dispatcher.BeginInvoke(() =>
        {
            _notificationItems.Insert(0, n);
            while (_notificationItems.Count > 200) _notificationItems.RemoveAt(_notificationItems.Count - 1);
            try { _logging.WriteNotification(n); } catch { }
        });
    }

    private void UiTick(object? sender, EventArgs e)
    {
        var (bIn, bOut) = _aggregation.SampleAndResetInterval();

        // Делим на фактически прошедшее время: под нагрузкой Background-таймер
        // тикает реже 500 мс, и «bytes * 2» завышал бы скорость
        var timestamp = Stopwatch.GetTimestamp();
        double seconds = _lastUiTickTimestamp == 0
            ? 0.5
            : (timestamp - _lastUiTickTimestamp) / (double)Stopwatch.Frequency;
        _lastUiTickTimestamp = timestamp;
        if (seconds < 0.05) seconds = 0.5;

        long rateIn = (long)(bIn / seconds);
        long rateOut = (long)(bOut / seconds);
        _notifications.RecordTrafficSample(rateIn + rateOut);

        SpeedInText = ByteFormatter.FormatRate(rateIn);
        SpeedOutText = ByteFormatter.FormatRate(rateOut);

        if (UiUpdatesSuspended) return;

        TotalBytesInText = ByteFormatter.Format(_aggregation.TotalBytesIn);
        TotalBytesOutText = ByteFormatter.Format(_aggregation.TotalBytesOut);
        TotalPackets = _aggregation.TotalPackets;
        DroppedPackets = _captureService.DroppedPackets;
        ConnectionCount = Connections.Count;

        var now = DateTime.Now;
        _speedInPoints.Add(new DateTimePoint(now, rateIn));
        _speedOutPoints.Add(new DateTimePoint(now, rateOut));
        while (_speedInPoints.Count > 120) _speedInPoints.RemoveAt(0);
        while (_speedOutPoints.Count > 120) _speedOutPoints.RemoveAt(0);

        UpdateTopLists();

        if (++_inactivityRefreshCounter >= 60)
        {
            _inactivityRefreshCounter = 0;
            ConnectionsView.Refresh();
        }
    }

    private void ApplyChartTheme(Themes.AppTheme theme)
    {
        SKColor labelColor;
        SKColor separatorColor;
        if (theme == Themes.AppTheme.Light)
        {
            labelColor = new SKColor(0x1A, 0x1B, 0x20);
            separatorColor = new SKColor(0xD9, 0xDB, 0xE0);
        }
        else
        {
            labelColor = new SKColor(0xF1, 0xF1, 0xF3);
            separatorColor = new SKColor(0x3D, 0x3D, 0x45);
        }

        foreach (var axis in SpeedXAxes)
        {
            axis.LabelsPaint = new SolidColorPaint(labelColor);
            axis.SeparatorsPaint = new SolidColorPaint(separatorColor);
        }
        foreach (var axis in SpeedYAxes)
        {
            axis.LabelsPaint = new SolidColorPaint(labelColor);
            axis.SeparatorsPaint = new SolidColorPaint(separatorColor);
        }
    }

    private void UpdateTopLists()
    {
        var fresh = new List<TopEntry>(10);
        foreach (var t in _aggregation.TopIps(10))
        {
            var label = string.IsNullOrEmpty(t.RemoteHost) || t.RemoteHost == t.Ip ? t.Ip : t.RemoteHost;
            fresh.Add(new TopEntry { Key = label, Bytes = t.Bytes, Display = ByteFormatter.Format(t.Bytes) });
        }
        SyncTopList(TopIps, fresh);

        fresh = new List<TopEntry>(10);
        foreach (var t in _aggregation.TopProcesses(10))
            fresh.Add(new TopEntry { Key = t.Process, Bytes = t.Bytes, Display = ByteFormatter.Format(t.Bytes) });
        SyncTopList(TopProcesses, fresh);
    }

    // Точечное обновление вместо Clear+Add — иначе оба списка полностью
    // перерисовываются дважды в секунду, даже когда ничего не изменилось
    private static void SyncTopList(ObservableCollection<TopEntry> target, List<TopEntry> fresh)
    {
        for (int i = 0; i < fresh.Count; i++)
        {
            if (i < target.Count)
            {
                if (target[i] != fresh[i]) target[i] = fresh[i];
            }
            else
            {
                target.Add(fresh[i]);
            }
        }
        while (target.Count > fresh.Count)
            target.RemoveAt(target.Count - 1);
    }

    private bool FilterConnection(object obj)
    {
        if (obj is not ConnectionAggregate c) return false;

        if (DateTime.Now - c.LastSeen > ConnectionInactivityTimeout)
            return false;

        if (HideUnknownProcess && (string.IsNullOrEmpty(c.ProcessName) || c.ProcessName == "unknown"))
            return false;

        if (ScopeFilter == "Только локальный" && !c.IsLocal) return false;
        if (ScopeFilter == "Только внешний" && c.IsLocal) return false;

        if (!string.IsNullOrWhiteSpace(IpFilter))
        {
            var f = IpFilter.Trim();
            if (!c.LocalIp.Contains(f, StringComparison.OrdinalIgnoreCase) &&
                !c.RemoteIp.Contains(f, StringComparison.OrdinalIgnoreCase) &&
                !c.RemoteHost.Contains(f, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        if (!string.IsNullOrWhiteSpace(IpRangeFrom) && !string.IsNullOrWhiteSpace(IpRangeTo))
        {
            if (!IpRangeHelper.InRange(c.LocalIp, IpRangeFrom, IpRangeTo) &&
                !IpRangeHelper.InRange(c.RemoteIp, IpRangeFrom, IpRangeTo))
                return false;
        }
        if (!string.IsNullOrWhiteSpace(ProcessFilter))
        {
            if (!c.ProcessName.Contains(ProcessFilter.Trim(), StringComparison.OrdinalIgnoreCase))
                return false;
        }
        if (!string.IsNullOrWhiteSpace(ProtocolFilter) && ProtocolFilter != "All")
        {
            if (!string.Equals(c.Protocol, ProtocolFilter, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var s = SearchText.Trim();
            if (!c.LocalIp.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.RemoteIp.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.RemoteHost.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.Sni.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.AppLabel.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.ProcessName.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.Protocol.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.Service.Contains(s, StringComparison.OrdinalIgnoreCase) &&
                !c.RemotePort.ToString().Contains(s) &&
                !c.LocalPort.ToString().Contains(s))
                return false;
        }
        return true;
    }

    partial void OnSearchTextChanged(string value) => RefreshFilter();
    partial void OnIpFilterChanged(string value) => RefreshFilter();
    partial void OnIpRangeFromChanged(string value) => RefreshFilter();
    partial void OnIpRangeToChanged(string value) => RefreshFilter();
    partial void OnProcessFilterChanged(string value) => RefreshFilter();

    partial void OnProtocolFilterChanged(string value)
    {
        SettingsService.Current.ProtocolFilter = value;
        RefreshFilter();
    }

    partial void OnHideUnknownProcessChanged(bool value)
    {
        SettingsService.Current.HideUnknownProcess = value;
        RefreshFilter();
    }

    partial void OnScopeFilterChanged(string value)
    {
        SettingsService.Current.ScopeFilter = value;
        RefreshFilter();
    }

    partial void OnSelectedInterfaceChanged(NetworkInterfaceInfo? value)
    {
        if (value is not null) SettingsService.Current.InterfaceName = value.Name;
    }

    partial void OnLogToFileChanged(bool value) => SettingsService.Current.LogToFile = value;
    partial void OnLogFormatChanged(LogFormat value) => SettingsService.Current.LogFormat = value.ToString();

    partial void OnSelectedGroupingChanged(string value)
    {
        SettingsService.Current.Grouping = value;
        ConnectionsView.GroupDescriptions.Clear();
        switch (value)
        {
            case "По процессу":
                ConnectionsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ConnectionAggregate.ProcessName)));
                break;
            case "По удалённому хосту":
                ConnectionsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ConnectionAggregate.RemoteHostOrIp)));
                break;
            case "По протоколу":
                ConnectionsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ConnectionAggregate.Protocol)));
                break;
            case "По зоне":
                ConnectionsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ConnectionAggregate.ScopeText)));
                break;
        }
    }

    public void Dispose()
    {
        _uiTimer.Stop();
        using (var wh = new ManualResetEvent(false))
        {
            if (_pruneTimer.Dispose(wh)) wh.WaitOne(1000);
        }
        Stop();

        Themes.ThemeManager.ThemeChanged -= _themeChangedHandler;
        _notifications.NotificationRaised -= OnNotificationRaised;
        _aggregation.ConnectionCreated -= OnConnectionCreated;
        _aggregation.RemoteIpCreated -= OnRemoteIpCreated;
        _aggregation.ConnectionsPruned -= OnConnectionsPruned;
        _aggregation.RemoteIpsPruned -= OnRemoteIpsPruned;
        _dns.Resolved -= OnDnsResolved;

        _captureService.Dispose();
        _etwTracker.Dispose();
        _processResolver.Dispose();
        _logging.Dispose();
        _dns.Dispose();
        _consumerCts?.Dispose();
    }
}

public sealed record TopEntry
{
    public string Key { get; init; } = string.Empty;
    public long Bytes { get; init; }
    public string Display { get; init; } = string.Empty;
}
