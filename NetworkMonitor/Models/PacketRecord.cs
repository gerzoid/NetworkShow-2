using System;

namespace NetworkMonitor.Models;

public sealed class PacketRecord
{
    public DateTime Timestamp { get; init; }
    public string SourceIp { get; init; } = string.Empty;
    public string DestinationIp { get; init; } = string.Empty;
    public int SourcePort { get; init; }
    public int DestinationPort { get; init; }
    public string Protocol { get; init; } = string.Empty;
    public int Size { get; init; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public TrafficDirection Direction { get; init; }
    public string? Sni { get; init; }
    /// <summary>Флаги TCP (SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01); 0 для не-TCP.</summary>
    public byte TcpFlags { get; init; }
    /// <summary>Имя из DNS-запроса (UDP/53), только при включённом сборе сайтов.</summary>
    public string? DnsName { get; init; }
    /// <summary>Порядковый номер TCP и длина данных — для метрик качества (повторные передачи).</summary>
    public uint TcpSeq { get; init; }
    public int PayloadLength { get; init; }
    /// <summary>Протокол, определённый по содержимому (ssh, rdp, bittorrent, wireguard, openvpn, tls…), а не по порту.</summary>
    public string? AppProto { get; init; }
    /// <summary>JA3-отпечаток TLS-клиента (MD5) — только в пакете ClientHello.</summary>
    public string? Ja3 { get; init; }

    public string TimeText => Timestamp.ToString("HH:mm:ss.fff");
    public string DirectionText => Direction == TrafficDirection.Outbound ? "↑" : "↓";
}

public enum TrafficDirection
{
    Unknown,
    Inbound,
    Outbound
}
