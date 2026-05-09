using System;
using CommunityToolkit.Mvvm.ComponentModel;
using NetworkMonitor.Helpers;

namespace NetworkMonitor.Models;

public sealed partial class ConnectionAggregate : ObservableObject
{
    public string Key { get; init; } = string.Empty;

    public string LocalIp { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public string RemoteIp { get; init; } = string.Empty;
    public int RemotePort { get; init; }
    public string Protocol { get; init; } = string.Empty;
    public string Service { get; init; } = string.Empty;
    public IpScope RemoteScope { get; init; }
    public DateTime FirstSeen { get; init; } = DateTime.Now;

    public string ScopeText => IpClassifier.Display(RemoteScope);
    public bool IsLocal => IpClassifier.IsLocal(RemoteScope);

    [ObservableProperty]
    private string remoteHost = string.Empty;

    [ObservableProperty]
    private string sni = string.Empty;

    [ObservableProperty]
    private string appLabel = string.Empty;

    [ObservableProperty]
    private string processName = string.Empty;

    [ObservableProperty]
    private int processId;

    [ObservableProperty]
    private long packets;

    [ObservableProperty]
    private long bytes;

    [ObservableProperty]
    private long bytesIn;

    [ObservableProperty]
    private long bytesOut;

    [ObservableProperty]
    private DateTime lastSeen;

    public string Endpoint => $"{LocalIp}:{LocalPort} ↔ {RemoteIp}:{RemotePort}";
    public string RemoteEndpoint => $"{RemoteIp}:{RemotePort}";
    public string LocalEndpoint => $"{LocalIp}:{LocalPort}";

    public string RemoteHostOrIp => string.IsNullOrEmpty(RemoteHost) || RemoteHost == RemoteIp ? RemoteIp : RemoteHost;

    public string SniOrHost
    {
        get
        {
            if (!string.IsNullOrEmpty(Sni)) return Sni;
            if (!string.IsNullOrEmpty(RemoteHost) && RemoteHost != RemoteIp) return RemoteHost;
            return string.Empty;
        }
    }

    partial void OnRemoteHostChanged(string value)
    {
        OnPropertyChanged(nameof(RemoteHostOrIp));
        OnPropertyChanged(nameof(SniOrHost));
        Reclassify();
    }

    partial void OnSniChanged(string value)
    {
        OnPropertyChanged(nameof(SniOrHost));
        Reclassify();
    }

    private void Reclassify()
    {
        var src = !string.IsNullOrEmpty(Sni) ? Sni : RemoteHost;
        AppLabel = ServiceClassifier.Classify(src);
    }
}
