using System.Linq;
using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;

namespace NetworkMonitor.Models;

/// <summary>Сетевой адаптер для выбора захвата: имя, адреса, тип, состояние и «живая» скорость (чтобы видеть, где идёт трафик).</summary>
public sealed partial class NetworkInterfaceInfo : ObservableObject
{
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string FriendlyName { get; init; } = string.Empty;

    /// <summary>IPv4-адреса через запятую (пусто — нет IPv4).</summary>
    public string Addresses { get; set; } = string.Empty;
    /// <summary>Ethernet, Wi-Fi, виртуальный, туннель…</summary>
    public string Kind { get; set; } = string.Empty;
    public string SpeedText { get; set; } = string.Empty;
    public bool IsUp { get; set; } = true;
    /// <summary>Есть шлюз по умолчанию — через этот адаптер обычно идёт интернет.</summary>
    public bool IsDefault { get; set; }

    [ObservableProperty] private string rateText = string.Empty;
    [ObservableProperty] private bool isActive;

    // Служебное для расчёта скорости
    internal NetworkInterface? Nic;
    internal long LastRx, LastTx, LastTicks;

    public string DisplayName => string.IsNullOrWhiteSpace(FriendlyName) ? Description : FriendlyName;

    /// <summary>Строка для закрытого списка: имя и IP.</summary>
    public string Summary => Addresses.Length > 0 ? $"{DisplayName} · {Addresses}" : DisplayName;

    /// <summary>Подробности для выпадающего списка.</summary>
    public string Details => string.Join(" · ", new[]
    {
        Addresses.Length > 0 ? Addresses : "нет IPv4",
        Kind,
        SpeedText,
        IsUp ? string.Empty : "отключён"
    }.Where(x => !string.IsNullOrEmpty(x)));

    public override string ToString() => DisplayName;
}
