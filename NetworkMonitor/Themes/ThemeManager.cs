using System;
using System.Linq;
using System.Windows;

namespace NetworkMonitor.Themes;

public enum AppTheme
{
    Dark,
    Light
}

public static class ThemeManager
{
    public static AppTheme Current { get; private set; } = AppTheme.Dark;

    public static event EventHandler<AppTheme>? ThemeChanged;

    public static void Apply(AppTheme theme)
    {
        var app = Application.Current;
        if (app is null) return;

        var dicts = app.Resources.MergedDictionaries;
        for (int i = dicts.Count - 1; i >= 0; i--)
        {
            var src = dicts[i].Source?.OriginalString ?? string.Empty;
            if (src.Contains("DarkTheme") || src.Contains("LightTheme"))
                dicts.RemoveAt(i);
        }

        var path = theme == AppTheme.Dark ? "Themes/DarkTheme.xaml" : "Themes/LightTheme.xaml";
        dicts.Add(new ResourceDictionary { Source = new Uri(path, UriKind.Relative) });
        Current = theme;
        ThemeChanged?.Invoke(null, theme);
    }

    public static void Toggle() => Apply(Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);
}
