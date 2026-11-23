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

    // Живые счётчики: пишет поток агрегации на каждый пакет без PropertyChanged,
    // в привязанные свойства их переносит PublishCounters() по таймеру UI
    internal long LivePackets;
    internal long LiveBytes;
    internal long LiveBytesIn;
    internal long LiveBytesOut;
    internal DateTime LiveLastSeen;

    // Метрики потока (как в NetFlow) и качества сети — пишет поток агрегации
    internal long LiveRetransmits;
    internal long LiveResets;
    internal double LiveRttMs;
    internal long LiveIatCount;
    internal double LiveIatMean;
    internal double LiveIatM2;
    internal long LastPacketTicks;
    internal long SynOutTicks;
    internal long SynAckOutTicks;
    internal uint HighSeqOut, HighSeqIn;
    internal bool HasSeqOut, HasSeqIn;
    internal bool GeoDone;

    public void PublishCounters()
    {
        Packets = LivePackets;
        Bytes = LiveBytes;
        BytesIn = LiveBytesIn;
        BytesOut = LiveBytesOut;
        LastSeen = LiveLastSeen;
        Retransmits = LiveRetransmits;
        Resets = LiveResets;
        RttMs = LiveRttMs;
        IatMeanMs = LiveIatMean;
        IatCv = LiveIatCount > 2 && LiveIatMean > 0 ? Math.Sqrt(LiveIatM2 / LiveIatCount) / LiveIatMean : 0;
    }

    /// <summary>Длительность потока.</summary>
    public TimeSpan Duration => LastSeen > FirstSeen ? LastSeen - FirstSeen : TimeSpan.Zero;
    public string DurationText => Duration.TotalHours >= 1 ? Duration.ToString(@"h\:mm\:ss") : Duration.ToString(@"m\:ss");
    public long AvgPacketSize => Packets > 0 ? Bytes / Packets : 0;
    /// <summary>Доля исходящего в общем объёме (0…1): около 1 — загрузка/утечка, около 0 — скачивание.</summary>
    public double OutShare => Bytes > 0 ? (double)BytesOut / Bytes : 0;
    public string RttText => RttMs > 0 ? $"{RttMs:F0} мс" : string.Empty;
    public double RetransmitPercent => Packets > 0 ? 100.0 * Retransmits / Packets : 0;
    public string AppProtoText => AppProto switch
    {
        "tls" => "TLS", "ssh" => "SSH", "rdp" => "RDP", "http" => "HTTP", "bittorrent" => "BitTorrent", "wireguard" => "WireGuard",
        "openvpn" => "OpenVPN", "smb" => "SMB", "ftp" => "FTP", "smtp" => "SMTP", "pop3" => "POP3", "imap" => "IMAP",
        "telnet" => "Telnet", "quic" => "QUIC", "" or null => string.Empty, var other => other
    };


    public string ScopeText => IpClassifier.Display(RemoteScope);
    public bool IsLocal => IpClassifier.IsLocal(RemoteScope);

    [ObservableProperty]
    private string remoteHost = string.Empty;

    /// <summary>Своё имя адреса, заданное пользователем.</summary>
    [ObservableProperty]
    private string alias = string.Empty;

    /// <summary>Протокол, определённый по содержимому пакетов (а не по порту).</summary>
    [ObservableProperty]
    private string appProto = string.Empty;

    /// <summary>JA3-отпечаток TLS-клиента.</summary>
    [ObservableProperty]
    private string ja3 = string.Empty;

    /// <summary>Категория сайта: стриминг, соцсети, реклама и трекеры, CDN, облака…</summary>
    [ObservableProperty]
    private string category = string.Empty;

    /// <summary>Страна адреса (двухбуквенный код) и провайдер (ASN) по встроенной базе.</summary>
    [ObservableProperty]
    private string country = string.Empty;

    [ObservableProperty]
    private string asnText = string.Empty;

    [ObservableProperty]
    private double rttMs;

    [ObservableProperty]
    private long retransmits;

    [ObservableProperty]
    private long resets;

    [ObservableProperty]
    private double iatMeanMs;

    [ObservableProperty]
    private double iatCv;

    partial void OnAppProtoChanged(string value) => OnPropertyChanged(nameof(AppProtoText));
    partial void OnRttMsChanged(double value) => OnPropertyChanged(nameof(RttText));

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
        var cat = DomainCategories.Classify(src);
        if (cat.Length > 0) Category = cat;
    }
}
