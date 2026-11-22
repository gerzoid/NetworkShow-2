using System;
using System.Linq;
using System.Text;
using System.Windows;
using NetworkMonitor.Helpers;
using NetworkMonitor.Services;
using NetworkMonitor.ViewModels;

namespace NetworkMonitor;

/// <summary>Окно «Очистка данных за период»: предпросмотр и удаление логов/журналов на диске и данных в памяти.</summary>
public partial class CleanupWindow : Window
{
    private static readonly (string Text, TimeSpan? Span)[] Periods =
    {
        ("Старше 1 дня", TimeSpan.FromDays(1)),
        ("Старше 7 дней", TimeSpan.FromDays(7)),
        ("Старше 30 дней", TimeSpan.FromDays(30)),
        ("Старше 90 дней", TimeSpan.FromDays(90)),
        ("Все данные", null)
    };

    private readonly MainViewModel _vm;
    private bool _ready;

    public CleanupWindow(MainViewModel vm)
    {
        _vm = vm;
        InitializeComponent();
        PeriodBox.ItemsSource = Periods.Select(p => p.Text).ToList();
        PeriodBox.SelectedIndex = 1;
        _ready = true;
        UpdatePreview();
    }

    private TimeSpan? Span => Periods[Math.Max(0, PeriodBox.SelectedIndex)].Span;

    private CleanupKinds Kinds()
    {
        var k = CleanupKinds.None;
        if (TrafficBox.IsChecked == true) k |= CleanupKinds.TrafficLogs;
        if (NotifyLogBox.IsChecked == true) k |= CleanupKinds.NotificationLog;
        if (ExportsBox.IsChecked == true) k |= CleanupKinds.Exports;
        if (CrashBox.IsChecked == true) k |= CleanupKinds.CrashLog;
        return k;
    }

    private void Options_Changed(object sender, RoutedEventArgs e)
    {
        if (_ready) UpdatePreview();
    }

    private void UpdatePreview()
    {
        var disk = DataCleanupService.Preview(DataCleanupService.DefaultDir, Span, Kinds());
        var (conns, notes) = _vm.PreviewMemoryCleanup(Span);
        if (ConnBox.IsChecked != true) conns = 0;
        if (NotesBox.IsChecked != true) notes = 0;

        var sb = new StringBuilder();
        sb.AppendLine($"На диске: файлов {disk.Files} ({ByteFormatter.Format(disk.Bytes)}), строк журнала уведомлений {disk.NotificationLines}.");
        sb.Append($"В памяти: соединений {conns}, уведомлений {notes}.");
        PreviewText.Text = sb.ToString();
        CleanButton.IsEnabled = disk.Files + disk.NotificationLines + conns + notes > 0;
    }

    private void Clean_Click(object sender, RoutedEventArgs e)
    {
        if (Span is null &&
            MessageBox.Show(this, "Удалить ВСЕ выбранные данные без ограничения по времени? Это нельзя отменить.",
                "Очистка данных", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        var disk = DataCleanupService.Execute(DataCleanupService.DefaultDir, Span, Kinds());
        _vm.CleanMemory(Span, ConnBox.IsChecked == true, NotesBox.IsChecked == true);

        var msg = $"Очистка выполнена: файлов {disk.Files} ({ByteFormatter.Format(disk.Bytes)}), строк журнала {disk.NotificationLines}" +
                  (disk.Skipped > 0 ? $"; не удалось удалить {disk.Skipped} (используются программой)" : string.Empty) + ".";
        _vm.StatusText = msg;
        UpdatePreview();
        PreviewText.Text = msg + Environment.NewLine + PreviewText.Text;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
