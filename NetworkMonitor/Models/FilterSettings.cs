using CommunityToolkit.Mvvm.ComponentModel;

namespace NetworkMonitor.Models;

public sealed partial class FilterSettings : ObservableObject
{
    [ObservableProperty]
    private string ipFilter = string.Empty;

    [ObservableProperty]
    private string ipRangeFrom = string.Empty;

    [ObservableProperty]
    private string ipRangeTo = string.Empty;

    [ObservableProperty]
    private string processFilter = string.Empty;

    [ObservableProperty]
    private string protocolFilter = "All";

    [ObservableProperty]
    private int minSize;

    [ObservableProperty]
    private int maxSize;

    [ObservableProperty]
    private string searchText = string.Empty;
}
