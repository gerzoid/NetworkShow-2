using System;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using NetworkMonitor.Models;

namespace NetworkMonitor.Helpers;

/// <summary>Сопоставляет устройство Npcap (\Device\NPF_{GUID}) с адаптером Windows и считает его живую скорость.</summary>
public static class InterfaceProbe
{
    private static readonly string[] VirtualMarkers =
    {
        "virtual", "vmware", "hyper-v", "vethernet", "virtualbox", "tap-", "wintun", "tailscale", "wireguard",
        "vpn", "loopback", "bluetooth", "wi-fi direct", "npcap", "miniport"
    };

    public static NetworkInterface? FindNic(string pcapName)
    {
        var m = Regex.Match(pcapName ?? string.Empty, @"\{[0-9A-Fa-f\-]+\}");
        if (!m.Success) return null;
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => string.Equals(n.Id, m.Value, StringComparison.OrdinalIgnoreCase));
        }
        catch { return null; }
    }

    /// <summary>Заполняет адреса, тип, скорость и признак основного адаптера.</summary>
    public static void Fill(NetworkInterfaceInfo info)
    {
        var nic = FindNic(info.Name);
        info.Nic = nic;
        if (nic is null) return;

        try
        {
            info.IsUp = nic.OperationalStatus == OperationalStatus.Up;
            var props = nic.GetIPProperties();
            info.Addresses = string.Join(", ", props.UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()));
            info.IsDefault = info.IsUp && props.GatewayAddresses.Any(g =>
                !g.Address.Equals(System.Net.IPAddress.Any) && !g.Address.Equals(System.Net.IPAddress.IPv6Any));

            var text = (nic.Name + " " + nic.Description).ToLowerInvariant();
            info.Kind = nic.NetworkInterfaceType switch
            {
                NetworkInterfaceType.Wireless80211 => "Wi-Fi",
                NetworkInterfaceType.Loopback => "Loopback",
                NetworkInterfaceType.Tunnel => "Туннель",
                NetworkInterfaceType.Ppp => "PPP/VPN",
                _ => VirtualMarkers.Any(text.Contains) ? "виртуальный" : "Ethernet"
            };
            if (nic.Speed > 0 && info.IsUp)
                info.SpeedText = nic.Speed >= 1_000_000_000 ? $"{nic.Speed / 1_000_000_000.0:0.#} Гбит/с" : $"{nic.Speed / 1_000_000} Мбит/с";
        }
        catch { }
    }

    /// <summary>Обновляет скорость по разнице счётчиков адаптера с прошлого вызова.</summary>
    public static void Sample(NetworkInterfaceInfo info)
    {
        var nic = info.Nic;
        if (nic is null || !info.IsUp) { info.RateText = string.Empty; return; }
        try
        {
            var st = nic.GetIPStatistics();
            long rx = st.BytesReceived, tx = st.BytesSent, now = Stopwatch.GetTimestamp();
            if (info.LastTicks != 0)
            {
                double sec = (now - info.LastTicks) / (double)Stopwatch.Frequency;
                if (sec > 0.2)
                {
                    long drx = Math.Max(0, rx - info.LastRx), dtx = Math.Max(0, tx - info.LastTx);
                    info.IsActive = drx + dtx > 0;
                    info.RateText = info.IsActive
                        ? $"↓ {ByteFormatter.FormatRate((long)(drx / sec))}   ↑ {ByteFormatter.FormatRate((long)(dtx / sec))}"
                        : "нет трафика";
                }
            }
            info.LastRx = rx; info.LastTx = tx; info.LastTicks = now;
        }
        catch { }
    }
}
