using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkMonitor.Models;
using NetworkMonitor.Services;

namespace NetworkMonitor.ViewModels;

/// <summary>Вкладка «Устройства (ARP)»: список устройств локальной сети, сканирование, доверие.</summary>
public sealed partial class LanDevicesViewModel : ObservableObject
{
    private readonly LanDeviceMonitor _monitor;
    private readonly Action<string> _status;
    private readonly Dispatcher _dispatcher;

    public ObservableCollection<LanDevice> Devices { get; } = new();

    [ObservableProperty] private LanDevice? selectedDevice;
    [ObservableProperty] private string summary = "Устройства ещё не найдены. Нажмите «Сканировать сеть».";
    [ObservableProperty] private bool isScanning;

    /// <summary>Вызывается после переименования (обновить имена в таблицах).</summary>
    public Action? Renamed { get; set; }

    /// <summary>Задаёт устройству своё имя (по MAC).</summary>
    public void Rename(LanDevice device, string name)
    {
        _monitor.Rename(device.Mac, name);
        _status(string.IsNullOrWhiteSpace(name) ? $"Имя устройства {device.Ip} сброшено." : $"Устройство {device.Ip} названо «{name.Trim()}».");
        Renamed?.Invoke();
    }

    public LanDevicesViewModel(LanDeviceMonitor monitor, Action<string> status, Dispatcher dispatcher)
    {
        _monitor = monitor;
        _status = status;
        _dispatcher = dispatcher;
        _monitor.Updated += snapshot => _dispatcher.BeginInvoke(() => Sync(snapshot));
    }

    private void Sync(IReadOnlyList<LanDevice> snapshot)
    {
        foreach (var d in snapshot)
            if (!Devices.Contains(d)) Devices.Add(d);

        // Сначала «в сети», затем по IP
        var ordered = Devices.OrderByDescending(d => d.IsOnline).ThenBy(d => d.IpSort, StringComparer.Ordinal).ToList();
        for (int i = 0; i < ordered.Count; i++)
        {
            int cur = Devices.IndexOf(ordered[i]);
            if (cur != i) Devices.Move(cur, i);
        }

        int online = Devices.Count(d => d.IsOnline), unknown = Devices.Count(d => !d.IsKnown);
        Summary = Devices.Count == 0
            ? "Устройства ещё не найдены. Нажмите «Сканировать сеть»."
            : $"Устройств: {Devices.Count} · в сети: {online} · не доверенных: {unknown}";
    }

    [RelayCommand]
    private async System.Threading.Tasks.Task ScanAsync()
    {
        if (IsScanning) return;
        IsScanning = true;
        _status("Сканирование локальной сети (ARP)…");
        try
        {
            int found = await _monitor.ScanAsync();
            _status($"Сканирование завершено: ответили {found} устройств.");
        }
        catch (Exception ex)
        {
            _status($"Ошибка сканирования: {ex.Message}");
        }
        finally { IsScanning = false; }
    }

    [RelayCommand]
    private void TrustSelected()
    {
        if (SelectedDevice is null) return;
        _monitor.Trust(SelectedDevice.Mac);
        _status($"Устройство {SelectedDevice.Ip} ({SelectedDevice.Mac}) отмечено как доверенное.");
    }

    [RelayCommand]
    private void TrustAll()
    {
        _monitor.TrustAll();
        _status("Все найденные устройства отмечены как доверенные.");
    }
}
