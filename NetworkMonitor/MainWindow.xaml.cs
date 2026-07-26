using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Windows;
using System.Windows.Controls;
using NetworkMonitor.Models;
using NetworkMonitor.ViewModels;
using Forms = System.Windows.Forms;

namespace NetworkMonitor;

public partial class MainWindow : Window
{
    private Forms.NotifyIcon? _trayIcon;
    private bool _isExiting;

    public MainWindow()
    {
        InitializeComponent();
        InitTrayIcon();
        Closing += MainWindow_Closing;
        Closed += (_, _) =>
        {
            (DataContext as MainViewModel)?.Dispose();
            _trayIcon?.Dispose();
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
