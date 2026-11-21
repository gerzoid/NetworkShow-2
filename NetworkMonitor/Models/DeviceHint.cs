namespace NetworkMonitor.Models;

/// <summary>Признак устройства, подслушанный в служебном трафике (DHCP, mDNS, SSDP).</summary>
/// <param name="Ip">IP источника (или IP из записи mDNS).</param>
/// <param name="Mac">MAC клиента, если он есть в пакете (DHCP).</param>
/// <param name="Kind">hostname, dhcp-vendor, mdns-host, name, service, model, ssdp-server, ssdp.</param>
public sealed record DeviceHint(string Ip, string? Mac, string Kind, string Text);
