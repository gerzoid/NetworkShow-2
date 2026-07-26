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

    public static void Save()
    {
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
