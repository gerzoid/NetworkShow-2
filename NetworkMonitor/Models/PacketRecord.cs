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

    public string TimeText => Timestamp.ToString("HH:mm:ss.fff");
    public string DirectionText => Direction == TrafficDirection.Outbound ? "↑" : "↓";
}

public enum TrafficDirection
{
    Unknown,
    Inbound,
    Outbound
}
