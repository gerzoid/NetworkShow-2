using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace NetworkMonitor;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    private Mutex? _singleInstanceMutex;
    private bool _ownsMutex;

    /// <summary>Windows завершает сеанс (shutdown/logoff) — окно не должно отменять закрытие.</summary>
    public static bool IsSessionEnding { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstanceMutex = new Mutex(true, @"Local\NetworkShow_SingleInstance", out _ownsMutex);
        if (!_ownsMutex)
        {
            MessageBox.Show("NetworkShow уже запущен. Проверьте значок в системном трее.",
                "NetworkShow", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += (_, args) =>
        {
            LogCrash(args.Exception);
            MessageBox.Show($"Непредвиденная ошибка: {args.Exception.Message}\n\nПодробности в logs\\crash.log.",
                "NetworkShow", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) => LogCrash(args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            LogCrash(args.Exception);
            args.SetObserved();
        };

        base.OnStartup(e);
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        IsSessionEnding = true;
        base.OnSessionEnding(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex)
        {
            try { _singleInstanceMutex?.ReleaseMutex(); } catch { }
        }
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }

    private static void LogCrash(Exception? ex)
    {
        if (ex is null) return;
        try
        {
            var dir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "crash.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch { }
    }
}
