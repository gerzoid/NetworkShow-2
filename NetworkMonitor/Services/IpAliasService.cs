using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace NetworkMonitor.Services;

/// <summary>
/// Свои имена для IP-адресов (например, «Телевизор в зале», «Рабочий сервер»). Хранятся в настройках,
/// показываются во всех таблицах. Для устройств локальной сети имя можно задать и по MAC на вкладке «Устройства (ARP)» —
/// оно подставляется через <see cref="LanNameLookup"/>, даже если у устройства сменился IP.
/// </summary>
public static class IpAliasService
{
    private static readonly ConcurrentDictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Имя, заданное пользователем устройству сети по IP (подключается LAN-монитором).</summary>
    public static Func<string, string?>? LanNameLookup { get; set; }

    public static void Load(IDictionary<string, string>? saved)
    {
        Map.Clear();
        if (saved is null) return;
        foreach (var kv in saved)
            if (!string.IsNullOrWhiteSpace(kv.Key) && !string.IsNullOrWhiteSpace(kv.Value))
                Map[kv.Key.Trim()] = kv.Value.Trim();
    }

    /// <summary>Имя для отображения: явное имя адреса, иначе имя устройства сети; пусто, если не задано.</summary>
    public static string Resolve(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return string.Empty;
        if (Map.TryGetValue(ip, out var name)) return name;
        try { return LanNameLookup?.Invoke(ip) ?? string.Empty; }
        catch { return string.Empty; }
    }

    /// <summary>Только имя, заданное именно этому адресу (без имён устройств сети).</summary>
    public static string Explicit(string ip) => Map.TryGetValue(ip, out var n) ? n : string.Empty;

    /// <summary>Задаёт имя; пустое имя удаляет запись.</summary>
    public static void Set(string ip, string? name)
    {
        ip = ip.Trim();
        if (ip.Length == 0) return;
        name = name?.Trim() ?? string.Empty;
        if (name.Length == 0) Map.TryRemove(ip, out _);
        else Map[ip] = name.Length > 80 ? name[..80] : name;

        SettingsService.Current.IpAliases = All().ToDictionary(x => x.Ip, x => x.Name);
        SettingsService.Save();
    }

    public static IReadOnlyList<(string Ip, string Name)> All() =>
        Map.Select(kv => (kv.Key, kv.Value)).OrderBy(x => x.Key, StringComparer.Ordinal).ToList();
}
