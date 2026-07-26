using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Windows;
using System.Windows.Controls;
using NetworkMonitor.Models;
using NetworkMonitor.Services;
using NetworkMonitor.ViewModels;
using Forms = System.Windows.Forms;

namespace NetworkMonitor;

public partial class MainWindow : Window
{
    private Forms.NotifyIcon? _trayIcon;
    private bool _isExiting;
    private bool _trayHintShown;

    public MainWindow()
    {
        InitializeComponent();
        RestoreWindowBounds();
        InitTrayIcon();
        HookViewModel();
        Closing += MainWindow_Closing;
        IsVisibleChanged += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
                vm.UiUpdatesSuspended = !IsVisible;
        };
        Closed += (_, _) =>
        {
            SaveWindowBounds();
            (DataContext as MainViewModel)?.Dispose();
            _trayIcon?.Dispose();
        };
    }

    private void RestoreWindowBounds()
    {
        var s = SettingsService.Current;
        if (s.WindowWidth < 400 || s.WindowHeight < 300) return;

        Width = s.WindowWidth;
        Height = s.WindowHeight;
        // Восстанавливаем позицию, только если окно попадает на видимую область
        // (монитор могли отключить)
        if (!double.IsNaN(s.WindowLeft) && !double.IsNaN(s.WindowTop) &&
            s.WindowLeft >= SystemParameters.VirtualScreenLeft - 50 &&
            s.WindowTop >= SystemParameters.VirtualScreenTop - 50 &&
            s.WindowLeft < SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - 100 &&
            s.WindowTop < SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - 100)
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = s.WindowLeft;
            Top = s.WindowTop;
        }
        if (s.WindowMaximized)
            WindowState = WindowState.Maximized;
    }

    private void SaveWindowBounds()
    {
        var s = SettingsService.Current;
        var bounds = WindowState == WindowState.Normal
            ? new Rect(Left, Top, Width, Height)
            : RestoreBounds;
        if (bounds.Width < 400 || bounds.Height < 300) return;
        s.WindowLeft = bounds.Left;
        s.WindowTop = bounds.Top;
        s.WindowWidth = bounds.Width;
        s.WindowHeight = bounds.Height;
        s.WindowMaximized = WindowState == WindowState.Maximized;
        SettingsService.Save();
    }

    private void HookViewModel()
    {
        if (DataContext is not MainViewModel vm) return;

        vm.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.SpeedInText) && _trayIcon is not null)
            {
                var text = $"NetworkShow  ↓ {vm.SpeedInText}  ↑ {vm.SpeedOutText}";
                _trayIcon.Text = text.Length <= 63 ? text : text[..63];
            }
        };

        // Критичные уведомления (чёрный список) при свёрнутом окне показываем balloon'ом
        vm.Notifications.CollectionChanged += (_, args) =>
        {
            if (args.Action != NotifyCollectionChangedAction.Add || IsVisible || _trayIcon is null) return;
            foreach (var item in args.NewItems!)
            {
                if (item is TrafficNotification { Severity: NotificationSeverity.Critical } n)
                    _trayIcon.ShowBalloonTip(5000, n.Title, n.Message, Forms.ToolTipIcon.Warning);
            }
        };
    }

    private void InitTrayIcon()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => ShowFromTray());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Выход", null, (_, _) => ExitApplication());

        _trayIcon = new Forms.NotifyIcon
        {
            Text = "NetworkShow",
            Visible = true,
            Icon = TryGetAppIcon(),
            ContextMenuStrip = menu
        };
        _trayIcon.DoubleClick += (_, _) => ShowFromTray();
        _trayIcon.MouseClick += (_, me) =>
        {
            if (me.Button == Forms.MouseButtons.Left) ShowFromTray();
        };
    }

    private static System.Drawing.Icon TryGetAppIcon()
    {
        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath))
            {
                var icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
                if (icon != null) return icon;
            }
        }
        catch { }

        return System.Drawing.SystemIcons.Application;
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        // При завершении сеанса Windows (shutdown/logoff) закрытие отменять нельзя
        if (_isExiting || App.IsSessionEnding) return;

        // Сворачиваем в трей вместо закрытия
        e.Cancel = true;
        Hide();

        if (!_trayHintShown)
        {
            _trayHintShown = true;
            _trayIcon?.ShowBalloonTip(3000, "NetworkShow",
                "Приложение продолжает работать в трее. Клик по значку — открыть, «Выход» — закрыть.",
                Forms.ToolTipIcon.Info);
        }
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void ExitApplication()
    {
        _isExiting = true;
        Close();
    }

    private void CopyConnection_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as MenuItem)?.DataContext is not ConnectionAggregate c) return;
        var text = string.Join("\t",
            c.ScopeText,
            c.ProcessName,
            c.ProcessId,
            c.Protocol,
            c.Service,
            c.AppLabel,
            c.LocalEndpoint,
            c.RemoteEndpoint,
            c.SniOrHost,
            c.Packets,
            c.BytesIn,
            c.BytesOut,
            c.Bytes,
            c.LastSeen.ToString("HH:mm:ss"));
        SafeSetClipboard(text);
    }

    private void OpenProcessFile_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as MenuItem)?.DataContext is not ConnectionAggregate c) return;
        OpenInExplorer(c.ProcessId, c.ProcessName);
    }

    private void CopyRemoteIp_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as MenuItem)?.DataContext is not RemoteIpAggregate ip) return;
        var text = string.Join("\t",
            ip.Ip,
            ip.RemoteHost,
            ip.ScopeText,
            ip.Connections,
            ip.Packets,
            ip.BytesIn,
            ip.BytesOut,
            ip.Bytes,
            ip.TopProcess,
            ip.TopProcessId,
            ip.FirstSeen.ToString("HH:mm:ss"),
            ip.LastSeen.ToString("HH:mm:ss"));
        SafeSetClipboard(text);
    }

    private void OpenProcessFileRemoteIp_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as MenuItem)?.DataContext is not RemoteIpAggregate ip) return;
        OpenInExplorer(ip.TopProcessId, ip.TopProcess);
    }

    private static string? ExtractRowIp(object sender) => (sender as MenuItem)?.DataContext switch
    {
        ConnectionAggregate c => c.RemoteIp,
        RemoteIpAggregate ip => ip.Ip,
        _ => null
    };

    private void CopyIp_Click(object sender, RoutedEventArgs e)
    {
        if (ExtractRowIp(sender) is { } ip) SafeSetClipboard(ip);
    }

    private void BlacklistIp_Click(object sender, RoutedEventArgs e)
    {
        if (ExtractRowIp(sender) is { } ip)
            (DataContext as MainViewModel)?.AddIpToBlacklist(ip);
    }

    private void WhitelistIp_Click(object sender, RoutedEventArgs e)
    {
        if (ExtractRowIp(sender) is { } ip)
            (DataContext as MainViewModel)?.AddIpToWhitelist(ip);
    }

    private void OpenInExplorer(int pid, string processName)
    {
        if (pid <= 0)
        {
            ShowProcessError($"Процесс «{processName}» — системный (PID={pid}). Файл недоступен.");
            return;
        }

        var path = TryGetProcessFilePath(pid);
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            ShowProcessError($"Не удалось получить путь к файлу процесса (PID={pid}). Возможно, нужны права администратора.");
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ShowProcessError($"Не удалось открыть проводник: {ex.Message}");
        }
    }

    private static string? TryGetProcessFilePath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var path = p.MainModule?.FileName;
            if (!string.IsNullOrEmpty(path)) return path;
        }
        catch { }

        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                var path = obj["ExecutablePath"]?.ToString();
                if (!string.IsNullOrEmpty(path)) return path;
            }
        }
        catch { }

        return null;
    }

    private static void SafeSetClipboard(string text)
    {
        try { Clipboard.SetText(text); }
        catch
        {
            try { Clipboard.SetDataObject(text); } catch { }
        }
    }

    private void ShowProcessError(string message)
    {
        MessageBox.Show(this, message, "NetworkShow", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
