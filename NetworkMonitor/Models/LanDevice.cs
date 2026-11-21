using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace NetworkMonitor.Models;

/// <summary>Запись таблицы ARP: IP и MAC соседа по сети.</summary>
public readonly record struct ArpEntry(string Ip, string Mac, bool IsStatic);

/// <summary>Устройство локальной сети (по MAC): адрес, имя, состояние и признак «доверенное».</summary>
public sealed partial class LanDevice : ObservableObject
{
    public string Mac { get; init; } = string.Empty;
    public DateTime FirstSeen { get; init; } = DateTime.Now;

    [ObservableProperty] private string ip = string.Empty;
    [ObservableProperty] private string name = string.Empty;
    [ObservableProperty] private bool isOnline;
    [ObservableProperty] private bool isKnown;
    [ObservableProperty] private bool isGateway;
    [ObservableProperty] private DateTime lastSeen = DateTime.Now;
    /// <summary>Производитель по MAC (OUI); пусто для случайных MAC.</summary>
    [ObservableProperty] private string vendor = string.Empty;
    /// <summary>Предположительный тип: телевизор, Android-приставка, телефон, принтер…</summary>
    [ObservableProperty] private string deviceType = string.Empty;
    /// <summary>Признаки из DHCP / mDNS / SSDP, по которым определён тип.</summary>
    [ObservableProperty] private string hintsText = string.Empty;

    internal readonly System.Collections.Generic.HashSet<string> HintSet = new();
    internal int NamePriority;

    partial void OnIpChanged(string value) => OnPropertyChanged(nameof(IpSort));
    partial void OnIsOnlineChanged(bool value) => OnPropertyChanged(nameof(StatusText));
    partial void OnIsKnownChanged(bool value) => OnPropertyChanged(nameof(TrustText));
    partial void OnIsGatewayChanged(bool value) => OnPropertyChanged(nameof(Role));

    /// <summary>Бит «локально администрируемый» в первом октете: телефоны и ПК генерируют случайный MAC для приватности.</summary>
    public bool IsRandomMac => IsRandom(Mac);
    public string MacKind => IsRandomMac ? "случайный (приватный)" : "аппаратный";
    public string StatusText => IsOnline ? "● в сети" : "○ не в сети";
    public string TrustText => IsKnown ? "доверенное" : "⚠ новое";
    public string Role => IsGateway ? "роутер / шлюз" : string.Empty;

    /// <summary>IP с выравниванием для сортировки (192.168.001.010).</summary>
    public string IpSort
    {
        get
        {
            var parts = Ip.Split('.');
            return parts.Length == 4 ? string.Join(".", Array.ConvertAll(parts, p => p.PadLeft(3, '0'))) : Ip;
        }
    }

    public static bool IsRandom(string mac)
    {
        if (mac.Length < 2) return false;
        return int.TryParse(mac.AsSpan(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var b) && (b & 0x02) != 0;
    }
}
