using System;

namespace NetworkMonitor.Models;

public enum NotificationSeverity
{
    Info,
    Warning,
    Critical
}

public sealed class TrafficNotification
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public NotificationSeverity Severity { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;

    public string TimeText => Timestamp.ToString("HH:mm:ss");
    public string SeverityText => Severity.ToString();
}
