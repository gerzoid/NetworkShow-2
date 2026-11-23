using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using NetworkMonitor.Models;
using NetworkMonitor.Services;

namespace NetworkMonitor.ViewModels;

public sealed partial class AnalyticsViewModel
{
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> siteCategories = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> countries = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> asns = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<AnalyticsRow> quality = Array.Empty<AnalyticsRow>();
    [ObservableProperty] private IReadOnlyList<ConnectionAggregate> flows = Array.Empty<ConnectionAggregate>();

    [ObservableProperty] private AnalyticsRow? selectedSiteCategory;
    [ObservableProperty] private AnalyticsRow? selectedCountry;
    [ObservableProperty] private AnalyticsRow? selectedAsn;
    [ObservableProperty] private AnalyticsRow? selectedQuality;

    partial void OnSelectedSiteCategoryChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedCountryChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedAsnChanged(AnalyticsRow? value) => UpdateDetails();
    partial void OnSelectedQualityChanged(AnalyticsRow? value) => UpdateDetails();

    private AnalyticsRow? ExtraRow(int tab) => tab switch
    {
        5 => SelectedSiteCategory,
        6 => SelectedCountry,
        7 => SelectedAsn,
        8 => SelectedQuality,
        _ => null
    };

    /// <summary>Категории сайтов, страны, провайдеры, качество связи и таблица потоков (как в NetFlow).</summary>
    private void RefreshExtra(List<ConnectionAggregate> conns)
    {
        string? kc = SelectedSiteCategory?.Name, kn = SelectedCountry?.Name, ka = SelectedAsn?.Name, kq = SelectedQuality?.Name;
        var sc = AnalyticsExtras.BySiteCategory(conns);
        var co = AnalyticsExtras.ByCountry(conns);
        var asn = AnalyticsExtras.ByAsn(conns);
        var q = AnalyticsExtras.ByQuality(conns);
        SiteCategories = sc; Countries = co; Asns = asn; Quality = q;
        SelectedSiteCategory = kc is null ? null : sc.FirstOrDefault(x => x.Name == kc);
        SelectedCountry = kn is null ? null : co.FirstOrDefault(x => x.Name == kn);
        SelectedAsn = ka is null ? null : asn.FirstOrDefault(x => x.Name == ka);
        SelectedQuality = kq is null ? null : q.FirstOrDefault(x => x.Name == kq);
        if (SelectedTabIndex == 5 && SelectedSiteCategory is null) SelectedSiteCategory = sc.FirstOrDefault();
        else if (SelectedTabIndex == 6 && SelectedCountry is null) SelectedCountry = co.FirstOrDefault();
        else if (SelectedTabIndex == 7 && SelectedAsn is null) SelectedAsn = asn.FirstOrDefault();
        else if (SelectedTabIndex == 8 && SelectedQuality is null) SelectedQuality = q.FirstOrDefault();
        Flows = conns.OrderByDescending(c => c.Bytes).Take(500).ToList();
    }
}
