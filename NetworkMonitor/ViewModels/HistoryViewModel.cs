using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkMonitor.Services;

namespace NetworkMonitor.ViewModels;

/// <summary>Вкладка «История»: поиск по соединениям и событиям за период из базы SQLite и недельный отчёт.</summary>
public sealed partial class HistoryViewModel : ObservableObject
{
    private readonly HistoryStore _store;
    private readonly Action<string> _status;
    private readonly Dispatcher _dispatcher = Dispatcher.CurrentDispatcher;

    /// <summary>Перед запросом сбросить текущие соединения в базу (чтобы свежие данные тоже были видны).</summary>
    public Action? BeforeQuery { get; set; }

    public string[] PeriodOptions { get; } = { "1 день", "7 дней", "30 дней", "90 дней" };

    [ObservableProperty] private string selectedPeriod = "7 дней";
    [ObservableProperty] private string searchText = string.Empty;
    [ObservableProperty] private bool isActive;
    [ObservableProperty] private string summary = string.Empty;
    [ObservableProperty] private IReadOnlyList<HistoryFlowRow> flows = Array.Empty<HistoryFlowRow>();
    [ObservableProperty] private IReadOnlyList<HistoryEventRow> events = Array.Empty<HistoryEventRow>();

    public HistoryViewModel(HistoryStore store, Action<string> status)
    {
        _store = store;
        _status = status;
    }

    partial void OnIsActiveChanged(bool value) { if (value) Refresh(); }
    partial void OnSelectedPeriodChanged(string value) { if (IsActive) Refresh(); }
    partial void OnSearchTextChanged(string value) { if (IsActive) Refresh(); }

    private DateTime From => DateTime.Now - TimeSpan.FromDays(SelectedPeriod switch { "1 день" => 1, "30 дней" => 30, "90 дней" => 90, _ => 7 });

    [RelayCommand]
    public void Refresh()
    {
        var from = From;
        var text = SearchText;
        var period = SelectedPeriod;
        Task.Run(() =>
        {
            try
            {
                BeforeQuery?.Invoke();
                var f = _store.QueryFlows(from, text);
                var e = _store.QueryEvents(from, text);
                _dispatcher.BeginInvoke(() =>
                {
                    Flows = f;
                    Events = e;
                    Summary = $"Соединений: {f.Count} · событий: {e.Count} · за {period}" + (f.Count >= 2000 ? " (показаны последние 2000)" : string.Empty);
                });
            }
            catch (Exception ex)
            {
                _dispatcher.BeginInvoke(() => Summary = "Ошибка запроса истории: " + ex.Message);
            }
        });
    }

    [RelayCommand]
    private void Report()
    {
        _status("Формирование отчёта…");
        Task.Run(() =>
        {
            try
            {
                BeforeQuery?.Invoke();
                var to = DateTime.Now;
                var path = ReportService.Save(_store.BuildReport(to.AddDays(-7), to));
                _dispatcher.BeginInvoke(() =>
                {
                    _status($"Отчёт за 7 дней сохранён: {path}");
                    try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch { }
                });
            }
            catch (Exception ex)
            {
                _dispatcher.BeginInvoke(() => _status("Не удалось сформировать отчёт: " + ex.Message));
            }
        });
    }
}
