using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;

namespace NetworkMonitor.ViewModels;

/// <summary>Режим «Кто читает мои шары»: независим от захвата пакетов (Npcap не нужен).</summary>
public sealed partial class ShareAccessViewModel : ObservableObject, IDisposable
{
    private readonly ShareAccessMonitor _monitor = new();
    private readonly Dispatcher _dispatcher = Dispatcher.CurrentDispatcher;
    private readonly string _logPath;
    private readonly object _logLock = new();

    public BoundedObservableCollection<ShareAccessEvent> Events { get; } = new(5000);
    public ICollectionView EventsView { get; }

    /// <summary>Оповещения для общей вкладки «Уведомления».</summary>
    public event EventHandler<TrafficNotification>? Alert;

    [ObservableProperty] private bool isRunning;
    [ObservableProperty] private string statusText = "Режим выключен.";
    [ObservableProperty] private string auditText = string.Empty;
    [ObservableProperty] private bool auditOk;
    [ObservableProperty] private string searchText = string.Empty;
    [ObservableProperty] private bool onlyDenied;
    [ObservableProperty] private bool onlyTunnel;
    [ObservableProperty] private bool hideSessions;
    [ObservableProperty] private int totalEvents;
    [ObservableProperty] private int deniedEvents;
    [ObservableProperty] private int clientCount;

    private readonly System.Collections.Generic.HashSet<string> _clients = new();

    public ShareAccessViewModel()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "logs");
        try { Directory.CreateDirectory(dir); } catch { }
        _logPath = Path.Combine(dir, "share-access.csv");

        EventsView = CollectionViewSource.GetDefaultView(Events);
        EventsView.Filter = Filter;

        _monitor.EventReceived += (_, e) => _dispatcher.BeginInvoke(() => AddEvent(e));
        _monitor.StatusChanged += (_, s) => _dispatcher.BeginInvoke(() => StatusText = s);
        RefreshAuditState();
    }

    partial void OnSearchTextChanged(string value) => EventsView.Refresh();
    partial void OnOnlyDeniedChanged(bool value) => EventsView.Refresh();
    partial void OnOnlyTunnelChanged(bool value) => EventsView.Refresh();
    partial void OnHideSessionsChanged(bool value) => EventsView.Refresh();

    private bool Filter(object o)
    {
        if (o is not ShareAccessEvent e) return false;
        if (OnlyDenied && !e.Denied) return false;
        if (OnlyTunnel && !e.IsTunnel) return false;
        if (HideSessions && e.Kind == ShareEventKind.Session) return false;
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var t = SearchText.Trim();
            bool Has(string s) => s.Contains(t, StringComparison.OrdinalIgnoreCase);
            if (!(Has(e.Client) || Has(e.User) || Has(e.Share) || Has(e.Path) || Has(e.Via) || Has(e.Access)))
                return false;
        }
        return true;
    }

    private void AddEvent(ShareAccessEvent e)
    {
        Events.Insert(0, e);
        TotalEvents++;
        if (e.Denied) DeniedEvents++;
        if (!string.IsNullOrEmpty(e.Client) && _clients.Add(e.Client)) ClientCount = _clients.Count;
        WriteLog(e);
        RaiseAlertIfNeeded(e);
    }

    private void RaiseAlertIfNeeded(ShareAccessEvent e)
    {
        // Уведомляем только о значимом: отказы, ошибки входа и первые подключения клиентов
        string who = $"{e.ClientText}{(string.IsNullOrEmpty(e.User) ? "" : $" ({e.User})")}{(e.IsTunnel ? $" через {e.Via}" : "")}";
        if (e.Kind == ShareEventKind.LogonFailed)
            Raise(NotificationSeverity.Critical, "Ошибка входа к шарам", $"{who} — неудачная авторизация");
        else if (e.Denied)
            Raise(NotificationSeverity.Warning, "Отказ доступа к шаре", $"{who}: {e.Share}\\{e.Path} [{e.Access}]");
        else if (e.Kind == ShareEventKind.Session)
            Raise(e.IsTunnel ? NotificationSeverity.Warning : NotificationSeverity.Info,
                "Подключение к шаре", $"{who} → {(string.IsNullOrEmpty(e.Share) ? "шара" : e.Share)}");
    }

    private void Raise(NotificationSeverity sev, string title, string msg) =>
        Alert?.Invoke(this, new TrafficNotification { Severity = sev, Title = title, Message = msg });

    private void WriteLog(ShareAccessEvent e)
    {
        try
        {
            lock (_logLock)
            {
                bool header = !File.Exists(_logPath);
                var sb = new StringBuilder();
                if (header) sb.AppendLine("timestamp,kind,source,client,client_port,user,share,path,access,result,via");
                sb.AppendLine(string.Join(',', new[]
                {
                    e.Timestamp.ToString("O", CultureInfo.InvariantCulture), e.Kind.ToString(), e.Source, e.Client,
                    e.ClientPort, e.User, e.Share, e.Path, e.Access, e.ResultText, e.Via
                }.Select(Csv)));
                File.AppendAllText(_logPath, sb.ToString(), Encoding.UTF8);
            }
        }
        catch { }
    }

    private static string Csv(string s) =>
        s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;

    private void RefreshAuditState()
    {
        switch (ShareAccessMonitor.GetAuditState())
        {
            case ShareAccessMonitor.AuditState.On:
                AuditOk = true;
                AuditText = "Аудит доступа к файлам: включён — видны все попытки, включая отказы.";
                break;
            case ShareAccessMonitor.AuditState.Partial:
                AuditOk = false;
                AuditText = "Аудит включён частично — нажмите «Включить аудит».";
                break;
            case ShareAccessMonitor.AuditState.Off:
                AuditOk = false;
                AuditText = "Аудит выключен: видны только текущие сессии и открытые файлы. Включите аудит для истории и отказов.";
                break;
            default:
                AuditOk = false;
                AuditText = "Состояние аудита неизвестно (нужны права администратора).";
                break;
        }
    }

    [RelayCommand]
    private void Toggle()
    {
        if (IsRunning)
        {
            _monitor.Stop();
            IsRunning = false;
        }
        else
        {
            RefreshAuditState();
            _monitor.Start();
            IsRunning = true;
        }
    }

    [RelayCommand]
    private void EnableAudit()
    {
        var answer = MessageBox.Show(
            "Будет изменена локальная политика аудита Windows: включены успехи и отказы для подкатегорий " +
            "«Общий файловый ресурс», «Подробный общий файловый ресурс» и «Вход». " +
            "Это увеличит объём журнала безопасности.\n\nПродолжить?",
            "Включить аудит доступа к шарам", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;

        bool ok = ShareAccessMonitor.EnableAudit();
        RefreshAuditState();
        if (!ok)
        {
            StatusText = "Не удалось включить аудит (нужен запуск от администратора, возможно мешает групповая политика).";
            return;
        }
        StatusText = "Аудит включён.";
        if (IsRunning) _monitor.RestartAuditWatcher();
    }

    [RelayCommand]
    private void Clear()
    {
        Events.Clear();
        _clients.Clear();
        TotalEvents = 0;
        DeniedEvents = 0;
        ClientCount = 0;
    }

    [RelayCommand]
    private void OpenLog()
    {
        try
        {
            if (File.Exists(_logPath))
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{_logPath}\"");
            else
                StatusText = "Файл журнала ещё не создан.";
        }
        catch { }
    }

    public void Dispose() => _monitor.Dispose();
}
