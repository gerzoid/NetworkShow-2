using System;
using CommunityToolkit.Mvvm.ComponentModel;
using NetworkMonitor.Helpers;

namespace NetworkMonitor.Models;

public sealed partial class RemoteIpAggregate : ObservableObject
{
    public string Ip { get; init; } = string.Empty;
    public IpScope Scope { get; init; }
    public DateTime FirstSeen { get; init; } = DateTime.Now;

    [ObservableProperty]
    private string remoteHost = string.Empty;

    [ObservableProperty]
    private long bytes;

    [ObservableProperty]
    private long bytesIn;

    [ObservableProperty]
    private long bytesOut;

    [ObservableProperty]
    private long packets;

    [ObservableProperty]
    private int connections;

    [ObservableProperty]
    private DateTime lastSeen;

    [ObservableProperty]
    private string topProcess = string.Empty;

    [ObservableProperty]
    private int topProcessId;

    // См. ConnectionAggregate: счётчики на каждый пакет, публикация по таймеру UI
    internal long LiveBytes;
    internal long LiveBytesIn;
    internal long LiveBytesOut;
    internal long LivePackets;
    internal DateTime LiveLastSeen;

    public void PublishCounters()
    {
        Bytes = LiveBytes;
        BytesIn = LiveBytesIn;
        BytesOut = LiveBytesOut;
        Packets = LivePackets;
        LastSeen = LiveLastSeen;
    }

    public string ScopeText => IpClassifier.Display(Scope);
    public bool IsLocal => IpClassifier.IsLocal(Scope);

    public string HostOrIp => string.IsNullOrEmpty(RemoteHost) || RemoteHost == Ip ? Ip : RemoteHost;

    partial void OnRemoteHostChanged(string value) => OnPropertyChanged(nameof(HostOrIp));
}
