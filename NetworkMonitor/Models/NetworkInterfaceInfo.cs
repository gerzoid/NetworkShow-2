namespace NetworkMonitor.Models;

public sealed class NetworkInterfaceInfo
{
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string FriendlyName { get; init; } = string.Empty;

    public override string ToString() => string.IsNullOrWhiteSpace(FriendlyName) ? Description : FriendlyName;
}
