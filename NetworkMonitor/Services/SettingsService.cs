using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace NetworkMonitor.Services;

public sealed class AppSettings
{
    public string Theme { get; set; } = "Dark";
    public string? InterfaceName { get; set; }
    public bool LogToFile { get; set; }
    /// <summary>Сбор и показ сайтов (SNI, DNS-имена). По умолчанию выключено: без явного включения пользователем не собирается.</summary>
    public bool CollectSites { get; set; }
    /// <summary>Детекторы аномалий и мониторинг входов Windows.</summary>
    public DetectionSettings Detection { get; set; } = new();
    /// <summary>Процессы, уже замеченные в сети (база для «новый процесс в сети»).</summary>
    public List<string> KnownProcesses { get; set; } = new();
    public string LogFormat { get; set; } = "Json";
    public string ProtocolFilter { get; set; } = "All";
    public string ScopeFilter { get; set; } = "Все";
    public string Grouping { get; set; } = "Без группировки";
    public bool HideUnknownProcess { get; set; }
    public List<string> Blacklist { get; set; } = new();
    public List<string> Whitelist { get; set; } = new();
    public double WindowLeft { get; set; } = double.NaN;
    public double WindowTop { get; set; } = double.NaN;
    public double WindowWidth { get; set; }
    public double WindowHeight { get; set; }
    public bool WindowMaximized { get; set; }
}

public sealed class DetectionSettings
{
    public bool Enabled { get; set; } = true;
    /// <summary>Скачивать фид IP управляющих серверов ботнетов (abuse.ch). Выключено по умолчанию.</summary>
    public bool ThreatFeed { get; set; }
    /// <summary>Сканирование портов: столько разных портов от одного IP...</summary>
    public int PortScanDistinctPorts { get; set; } = 15;
    /// <summary>...за это окно (сек).</summary>
    public int PortScanWindowSec { get; set; } = 30;
    /// <summary>Подбор пароля по сети: попыток подключения к служебному порту...</summary>
    public int BruteForceAttempts { get; set; } = 20;
    /// <summary>...за это окно (сек).</summary>
    public int BruteForceWindowSec { get; set; } = 60;
    /// <summary>Beaconing: минимум подключений к одной цели для оценки периодичности.</summary>
    public int BeaconMinConnections { get; set; } = 10;
    /// <summary>Beaconing: максимальный коэффициент вариации интервалов (σ/среднее).</summary>
    public double BeaconMaxVariation { get; set; } = 0.12;
    /// <summary>Всплеск исходящего: минимальный объём за 5 с (байт).</summary>
    public long ExfilMinBytes { get; set; } = 2_000_000;
    /// <summary>Всплеск исходящего: порог в сигмах над скользящим средним.</summary>
    public double ExfilSigma { get; set; } = 4.0;
    /// <summary>Неудачных входов Windows с одного источника за 5 мин для тревоги.</summary>
    public int FailedLogonThreshold { get; set; } = 5;
    /// <summary>Первый запуск: сколько минут «обучения» без тревог о новых процессах.</summary>
    public int LearningMinutes { get; set; } = 10;
}

public static class SettingsService
{
    private static readonly object SaveLock = new();
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "NetworkShow", "settings.json");

    public static AppSettings Current { get; private set; } = new();

    public static void Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var json = File.ReadAllText(FilePath);
                Current = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            }
        }
        catch
        {
            Current = new AppSettings();
        }
    }

    /// <summary>false — не писать файл настроек (тесты).</summary>
    public static bool Persist { get; set; } = true;

    public static void Save()
    {
        if (!Persist) return;
        try
        {
            lock (SaveLock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var json = JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(FilePath, json);
            }
        }
        catch { }
    }
}
