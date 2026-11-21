using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using NetworkMonitor.Services;

namespace NetworkMonitor.ViewModels;

/// <summary>Вкладка «Аналитика»: протоколы, сайты, процессы + детализация выбранной строки. Обновляется, пока вкладка открыта.</summary>
public sealed partial class AnalyticsViewModel : ObservableObject, IDisposable
{
    private readonly Func<List<ConnectionAggregate>> _source;
    private readonly Action<string> _status;
    private readonly DispatcherTimer _timer;

    public string[] PeriodOptions { get; } = { "5 минут", "1 час", "Всё время" };

    [ObservableProperty] private string selectedPeriod = "1 час";
    [ObservableProperty] private bool isActive;
    [ObservableProperty] private bool sitesEnabled;
    [ObservableProperty] private int selectedTabIndex;
    [ObservableProperty] private string summary = string.Empty;
    [ObservableProperty] private string detailTitle = "Выберите строку, чтобы увидеть соединения";

    [ObservableProperty] private IReadOnlyList<AnalyticsRow> protocols = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> sites = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> processes = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> zones = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> categories = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<ConnectionAggregate> details = Array.Empty<ConnectionAggregate>();

    [ObservableProperty] private AnalyticsRow? selectedProtocol;
    [ObservableProperty] private AnalyticsRow? selectedSite;
    [ObservableProperty] private AnalyticsRow? selectedProcess;
    [ObservableProperty] private AnalyticsRow? selectedZone;
    [ObservableProperty] private AnalyticsRow? selectedCategory;

    public AnalyticsViewModel(Func<List<ConnectionAggregate>> source, Action<string> status)
    {
        _source = source;
        _status = status;
        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += (_, _) => Refresh();
    }

    partial void OnIsActiveChanged(bool value)
    {
        if (value) { Refresh(); _timer.Start(); }
        else _timer.Stop();
    }

    partial void OnSelectedPeriodChanged(string value) { if (IsActive) Refresh(); }
    partial void OnSitesEnabledChanged(bool value) { if (IsActive) Refresh(); }
    partial void OnSelectedTabIndexChanged(int value) => UpdateDetails();
    partial void OnSelectedProtocolChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedSiteChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedProcessChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedZoneChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedCategoryChanged(AnalyticsRow? value) => UpdateDetails();

    [RelayCommand]
    public void Refresh()
    {
        TimeSpan? span = SelectedPeriod switch
        {
            "5 минут" => TimeSpan.FromMinutes(5),
            "1 час" => TimeSpan.FromHours(1),
            _ => null
        };

        var conns = AnalyticsService.Filter(_source(), span);
        var p = AnalyticsService.ByProtocol(conns);
        var s = SitesEnabled ? AnalyticsService.BySite(conns) : new List<AnalyticsRow>();
        var pr = AnalyticsService.ByProcess(conns);
        var z = AnalyticsService.ByZone(conns);
        var cat = AnalyticsService.ByCategory(conns);

        // Новые списки сбрасывают выделение в DataGrid — запоминаем выбранные по имени и восстанавливаем
        string? keepP = SelectedProtocol?.Name, keepS = SelectedSite?.Name, keepPr = SelectedProcess?.Name, keepZ = SelectedZone?.Name, keepC = SelectedCategory?.Name;
        Protocols = p;
        Sites = s;
        Processes = pr;
        Zones = z;
        Categories = cat;
        SelectedProtocol = keepP is null ? null : p.FirstOrDefault(x => x.Name == keepP);
        SelectedSite = keepS is null ? null : s.FirstOrDefault(x => x.Name == keepS);
        SelectedProcess = keepPr is null ? null : pr.FirstOrDefault(x => x.Name == keepPr);
        SelectedZone = keepZ is null ? null : z.FirstOrDefault(x => x.Name == keepZ);
        SelectedCategory = keepC is null ? null : cat.FirstOrDefault(x => x.Name == keepC);

        // Чтобы панель детализации не была пустой, выбираем первую строку активной вкладки
        if (SelectedTabIndex == 0 && SelectedProtocol is null) SelectedProtocol = p.FirstOrDefault();
        else if (SelectedTabIndex == 1 && SelectedSite is null) SelectedSite = s.FirstOrDefault();
        else if (SelectedTabIndex == 2 && SelectedProcess is null) SelectedProcess = pr.FirstOrDefault();
        else if (SelectedTabIndex == 3 && SelectedZone is null) SelectedZone = z.FirstOrDefault();
        else if (SelectedTabIndex == 4 && SelectedCategory is null) SelectedCategory = cat.FirstOrDefault();

        long total = conns.Sum(c => c.Bytes);
        Summary = $"Соединений: {conns.Count} · объём: {ByteFormatter.Format(total)} · " +
                  $"протоколов: {p.Count} · процессов: {pr.Count} · зон: {z.Count}" + (SitesEnabled ? $" · сайтов: {s.Count}" : string.Empty);
        UpdateDetails();
    }

    private void UpdateDetails()
    {
        var row = SelectedTabIndex switch
        {
            0 => SelectedProtocol,
            1 => SelectedSite,
            2 => SelectedProcess,
            3 => SelectedZone,
            _ => SelectedCategory
        };
        Details = row?.Items ?? (IReadOnlyList<ConnectionAggregate>)Array.Empty<ConnectionAggregate>();
        DetailTitle = row is null
            ? "Выберите строку, чтобы увидеть соединения"
            : $"Соединения: {row.Name} ({row.Items.Count}{(row.Connections > row.Items.Count ? $" из {row.Connections}" : string.Empty)})";
    }

    [RelayCommand]
    private void Export()
    {
        try
        {
            var dir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(dir);
            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            WriteCsv(Path.Combine(dir, $"analytics_protocols_{stamp}.csv"), Protocols);
            WriteCsv(Path.Combine(dir, $"analytics_processes_{stamp}.csv"), Processes);
            WriteCsv(Path.Combine(dir, $"analytics_zones_{stamp}.csv"), Zones);
            WriteCsv(Path.Combine(dir, $"analytics_categories_{stamp}.csv"), Categories);
            if (SitesEnabled) WriteCsv(Path.Combine(dir, $"analytics_sites_{stamp}.csv"), Sites);
            _status($"Аналитика сохранена в {dir}");
        }
        catch (Exception ex)
        {
            _status($"Ошибка экспорта аналитики: {ex.Message}");
        }
    }

    private static void WriteCsv(string path, IEnumerable<AnalyticsRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("name,extra,connections,hosts,packets,bytes,bytes_in,bytes_out,share,first_seen,last_seen");
        foreach (var r in rows)
        {
            sb.AppendLine(string.Join(",",
                Esc(r.Name), Esc(r.Extra),
                r.Connections.ToString(CultureInfo.InvariantCulture), r.Hosts.ToString(CultureInfo.InvariantCulture),
                r.Packets.ToString(CultureInfo.InvariantCulture), r.Bytes.ToString(CultureInfo.InvariantCulture),
                r.BytesIn.ToString(CultureInfo.InvariantCulture), r.BytesOut.ToString(CultureInfo.InvariantCulture),
                r.Share.ToString("F4", CultureInfo.InvariantCulture),
                r.FirstSeen.ToString("O", CultureInfo.InvariantCulture), r.LastSeen.ToString("O", CultureInfo.InvariantCulture)));
        }
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    private static string Esc(string s)
    {
        var q = ((char)34).ToString();
        return q + s.Replace(q, q + q) + q;
    }

    public void Dispose() => _timer.Stop();
}
