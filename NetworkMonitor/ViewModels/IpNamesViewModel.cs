using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkMonitor.Services;

namespace NetworkMonitor.ViewModels;

public sealed partial class IpNameEntry : ObservableObject
{
    public string Ip { get; init; } = string.Empty;
    [ObservableProperty] private string name = string.Empty;
    /// <summary>«задано вручную» или «устройство сети (MAC …)».</summary>
    public string Source { get; init; } = string.Empty;
    /// <summary>false — имя устройства сети: его меняют на вкладке «Устройства (ARP)».</summary>
    public bool IsEditable { get; init; } = true;
}

/// <summary>Вкладка «Имена адресов»: все заданные имена, добавление, правка, удаление.</summary>
public sealed partial class IpNamesViewModel : ObservableObject
{
    private readonly Func<IEnumerable<(string Ip, string Name, string Mac)>> _lanNames;
    private readonly Action<string, string> _setName;
    private readonly Action<string> _status;

    public ObservableCollection<IpNameEntry> Entries { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private string newIp = string.Empty;
    [ObservableProperty] private string newName = string.Empty;
    [ObservableProperty] private string filterText = string.Empty;
    [ObservableProperty] private IpNameEntry? selected;
    [ObservableProperty] private string summary = string.Empty;

    public IpNamesViewModel(Func<IEnumerable<(string Ip, string Name, string Mac)>> lanNames, Action<string, string> setName, Action<string> status)
    {
        _lanNames = lanNames;
        _setName = setName;
        _status = status;
        View = CollectionViewSource.GetDefaultView(Entries);
        View.Filter = o => o is IpNameEntry e && Matches(e);
        View.SortDescriptions.Add(new SortDescription(nameof(IpNameEntry.Ip), ListSortDirection.Ascending));
        Reload();
    }

    private bool Matches(IpNameEntry e) =>
        string.IsNullOrWhiteSpace(FilterText) ||
        e.Ip.Contains(FilterText.Trim(), StringComparison.OrdinalIgnoreCase) ||
        e.Name.Contains(FilterText.Trim(), StringComparison.OrdinalIgnoreCase);

    partial void OnFilterTextChanged(string value) => View.Refresh();

    /// <summary>Пересобирает список из сохранённых имён и имён устройств сети.</summary>
    public void Reload()
    {
        Entries.Clear();
        var explicitIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (ip, name) in IpAliasService.All())
        {
            explicitIps.Add(ip);
            Entries.Add(new IpNameEntry { Ip = ip, Name = name, Source = "задано вручную" });
        }
        foreach (var (ip, name, mac) in _lanNames())
        {
            if (explicitIps.Contains(ip)) continue;
            Entries.Add(new IpNameEntry { Ip = ip, Name = name, Source = $"устройство сети ({mac})", IsEditable = false });
        }
        Summary = $"Имён: {Entries.Count}";
    }

    [RelayCommand]
    private void Add()
    {
        var ip = NewIp.Trim();
        if (!IPAddress.TryParse(ip, out var addr))
        {
            _status("Введите корректный IP-адрес (IPv4 или IPv6).");
            return;
        }
        if (string.IsNullOrWhiteSpace(NewName))
        {
            _status("Введите имя для адреса.");
            return;
        }
        _setName(addr.ToString(), NewName);
        NewIp = string.Empty;
        NewName = string.Empty;
        _status($"Имя для {addr} сохранено.");
    }

    [RelayCommand]
    private void DeleteSelected()
    {
        if (Selected is null) return;
        if (!Selected.IsEditable)
        {
            _status("Имя устройства сети меняется на вкладке «Устройства (ARP)».");
            return;
        }
        _setName(Selected.Ip, string.Empty);
        _status($"Имя для {Selected.Ip} удалено.");
    }
}
