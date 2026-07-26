using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using NetworkMonitor.Helpers;
using NetworkMonitor.Models;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetworkMonitor.Services;

public sealed class PacketCaptureService : IDisposable
{
    private readonly ProcessResolverService _processResolver;
    private readonly Channel<PacketRecord> _channel;
    private ICaptureDevice? _device;
    private HashSet<IPAddress> _localAddresses = new();
    private long _droppedPackets;

    public ChannelReader<PacketRecord> Reader => _channel.Reader;
    public bool IsRunning { get; private set; }
    public long DroppedPackets => Interlocked.Read(ref _droppedPackets);

    public event EventHandler<string>? CaptureError;

    public PacketCaptureService(ProcessResolverService processResolver)
    {
        _processResolver = processResolver;
        _channel = Channel.CreateBounded<PacketRecord>(new BoundedChannelOptions(50_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = false,
            SingleWriter = false
        });
    }

    public IReadOnlyList<NetworkInterfaceInfo> ListInterfaces()
    {
        var result = new List<NetworkInterfaceInfo>();
        try
        {
            var devs = CaptureDeviceList.Instance;
            foreach (var dev in devs)
            {
                string friendly = dev.Description ?? dev.Name;
                if (dev is LibPcapLiveDevice live && !string.IsNullOrEmpty(live.Interface.FriendlyName))
                    friendly = live.Interface.FriendlyName;

                result.Add(new NetworkInterfaceInfo
                {
                    Name = dev.Name,
                    Description = dev.Description ?? string.Empty,
                    FriendlyName = friendly
                });
            }
        }
        catch (Exception ex)
        {
            CaptureError?.Invoke(this, $"Не удалось получить список интерфейсов: {ex.Message}");
        }
        return result;
    }

    public void Start(string deviceName)
    {
        if (IsRunning) return;
        var devs = CaptureDeviceList.Instance;
        var device = devs.FirstOrDefault(d => d.Name == deviceName) ?? devs.FirstOrDefault();
        if (device is null)
            throw new InvalidOperationException("Не найдены доступные сетевые интерфейсы. Установите Npcap.");

        _localAddresses = CollectLocalAddresses(device);
        device.OnPacketArrival += OnPacketArrival;
        try
        {
            device.Open(new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = 250,
                BufferSize = 16 * 1024 * 1024
            });
            device.StartCapture();
        }
        catch
        {
            device.OnPacketArrival -= OnPacketArrival;
            try { device.Close(); } catch { }
            throw;
        }
        _device = device;
        IsRunning = true;
    }

    public void Stop()
    {
        if (!IsRunning) return;
        try
        {
            _device?.StopCapture();
            _device?.Close();
        }
        catch (Exception ex)
        {
            CaptureError?.Invoke(this, $"Ошибка при остановке захвата: {ex.Message}");
        }
        finally
        {
            if (_device is not null) _device.OnPacketArrival -= OnPacketArrival;
            _device = null;
            IsRunning = false;
        }
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip = packet.Extract<IPPacket>();
            if (ip is null) return;

            int srcPort = 0, dstPort = 0;
            string protocol;
            string? sni = null;

            var tcp = packet.Extract<TcpPacket>();
            var udp = packet.Extract<UdpPacket>();
            if (tcp is not null)
            {
                srcPort = tcp.SourcePort;
                dstPort = tcp.DestinationPort;
                protocol = "TCP";

                var payload = tcp.PayloadData;
                if (payload is { Length: >= 43 } && payload[0] == 0x16 && payload[5] == 0x01)
                    sni = TlsSniExtractor.TryExtract(payload);
            }
            else if (udp is not null)
            {
                srcPort = udp.SourcePort;
                dstPort = udp.DestinationPort;
                protocol = "UDP";
            }
            else
            {
                protocol = ip.Protocol.ToString();
            }

            var direction = DetermineDirection(ip.SourceAddress, ip.DestinationAddress);

            var (pid, name) = (0, "unknown");
            if (protocol is "TCP" or "UDP")
            {
                (pid, name) = _processResolver.ResolveConnection(
                    protocol,
                    ip.SourceAddress.ToString(), srcPort,
                    ip.DestinationAddress.ToString(), dstPort);
            }

            var record = new PacketRecord
            {
                Timestamp = raw.Timeval.Date.ToLocalTime(),
                SourceIp = ip.SourceAddress.ToString(),
                DestinationIp = ip.DestinationAddress.ToString(),
                SourcePort = srcPort,
                DestinationPort = dstPort,
                Protocol = protocol,
                Size = raw.Data.Length,
                Direction = direction,
                ProcessId = pid,
                ProcessName = name,
                Sni = sni
            };

            if (!_channel.Writer.TryWrite(record))
                Interlocked.Increment(ref _droppedPackets);
        }
        catch
        {
            Interlocked.Increment(ref _droppedPackets);
        }
    }

    private TrafficDirection DetermineDirection(IPAddress src, IPAddress dst)
    {
        bool srcLocal = _localAddresses.Contains(src);
        bool dstLocal = _localAddresses.Contains(dst);
        if (srcLocal && !dstLocal) return TrafficDirection.Outbound;
        if (!srcLocal && dstLocal) return TrafficDirection.Inbound;
        return TrafficDirection.Unknown;
    }

    private static HashSet<IPAddress> CollectLocalAddresses(ICaptureDevice device)
    {
        var set = new HashSet<IPAddress>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                    set.Add(addr.Address);
            }
        }
        catch { }

        if (device is LibPcapLiveDevice live)
        {
            foreach (var addr in live.Addresses)
            {
                if (addr.Addr?.ipAddress is { } ip)
                    set.Add(ip);
            }
        }
        return set;
    }

    public void Dispose()
    {
        Stop();
        _channel.Writer.TryComplete();
    }
}
