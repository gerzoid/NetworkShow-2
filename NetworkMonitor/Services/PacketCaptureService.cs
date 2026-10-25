using System;
using System.Buffers.Binary;
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
    private int _linkType;

    private sealed record IpInfo(string Text, bool IsLocal);
    private const int IpCacheLimit = 65_536;
    private readonly Dictionary<IpKey, IpInfo> _ipCache = new();

    // Имена протоколов (кроме TCP/UDP) как у PacketDotNet, без Enum.ToString() на каждый пакет
    private static readonly string[] ProtocolNames = Enumerable.Range(0, 256)
        .Select(i => ((ProtocolType)i).ToString()).ToArray();

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
                if (dev is LibPcapLiveDevice live && !string.IsNullOrEmpty(live.Interface?.FriendlyName))
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
        _ipCache.Clear();
        device.OnPacketArrival += OnPacketArrival;
        try
        {
            device.Open(new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = 250,
                BufferSize = 16 * 1024 * 1024
            });
            _linkType = (int)device.LinkType;
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
            if (!PacketHeaderParser.SupportsLinkType(_linkType))
            {
                OnPacketArrivalSlow(e);
                return;
            }

            var data = e.Data;
            if (!PacketHeaderParser.TryParse(_linkType, data, out var h)) return;

            string protocol;
            string? sni = null;
            var payload = h.PayloadLength > 0 ? data.Slice(h.PayloadOffset, h.PayloadLength) : default;
            if (h.IsTcp)
            {
                protocol = "TCP";
                if (payload.Length >= 43 && payload[0] == 0x16 && payload[5] == 0x01)
                    sni = TlsSniExtractor.TryExtract(payload);
            }
            else if (h.IsUdp)
            {
                protocol = "UDP";
                // HTTP/3: SNI из QUIC Initial (только исходящие ClientHello на 443,
                // длинный заголовок типа Initial и датаграмма >= 1200 — дешёвый фильтр до криптографии)
                if (h.DestinationPort == 443 && payload.Length >= 1200 && (payload[0] & 0xF0) == 0xC0)
                    sni = QuicSniExtractor.TryExtract(payload.ToArray());
            }
            else
            {
                protocol = ProtocolNames[h.Protocol];
            }

            var src = GetIpInfo(h.Source, data, isSource: true);
            var dst = GetIpInfo(h.Destination, data, isSource: false);
            var direction = DetermineDirection(src.IsLocal, dst.IsLocal);

            Emit(e.Header.Timeval, src.Text, h.SourcePort, dst.Text, h.DestinationPort,
                protocol, data.Length, direction, sni);
        }
        catch
        {
            Interlocked.Increment(ref _droppedPackets);
        }
    }

    /// <summary>Разбор через PacketDotNet — для канальных уровней, которые не знает PacketHeaderParser.</summary>
    private void OnPacketArrivalSlow(PacketCapture e)
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

            if (dstPort == 443)
            {
                var payload = udp.PayloadData;
                if (payload is { Length: >= 1200 } && (payload[0] & 0xC0) == 0xC0)
                    sni = QuicSniExtractor.TryExtract(payload);
            }
        }
        else
        {
            protocol = ip.Protocol.ToString();
        }

        var direction = DetermineDirection(
            _localAddresses.Contains(ip.SourceAddress), _localAddresses.Contains(ip.DestinationAddress));

        Emit(raw.Timeval, ip.SourceAddress.ToString(), srcPort, ip.DestinationAddress.ToString(), dstPort,
            protocol, raw.Data.Length, direction, sni);
    }

    private void Emit(PosixTimeval timeval, string srcIp, int srcPort, string dstIp, int dstPort,
        string protocol, int size, TrafficDirection direction, string? sni)
    {
        var (pid, name) = (0, "unknown");
        if (protocol is "TCP" or "UDP")
            (pid, name) = _processResolver.ResolveConnection(protocol, srcIp, srcPort, dstIp, dstPort);

        var record = new PacketRecord
        {
            Timestamp = timeval.Date.ToLocalTime(),
            SourceIp = srcIp,
            DestinationIp = dstIp,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            Protocol = protocol,
            Size = size,
            Direction = direction,
            ProcessId = pid,
            ProcessName = name,
            Sni = sni
        };

        if (!_channel.Writer.TryWrite(record))
            Interlocked.Increment(ref _droppedPackets);
    }

    /// <summary>
    /// Строка и признак «локальный» для адреса из кэша: IPAddress и ToString() —
    /// только при первой встрече адреса, а не 4 раза на каждый пакет.
    /// Вызывается только из потока захвата.
    /// </summary>
    private IpInfo GetIpInfo(IpKey key, ReadOnlySpan<byte> frame, bool isSource)
    {
        if (_ipCache.TryGetValue(key, out var info)) return info;

        if (_ipCache.Count >= IpCacheLimit) _ipCache.Clear();
        var addr = key.IsV6 ? new IPAddress(ToBytesV6(key)) : new IPAddress(ToBytesV4(key));
        info = new IpInfo(addr.ToString(), _localAddresses.Contains(addr));
        _ipCache[key] = info;
        return info;
    }

    private static byte[] ToBytesV4(IpKey key)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, (uint)key.Lo);
        return b;
    }

    private static byte[] ToBytesV6(IpKey key)
    {
        var b = new byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(b, key.Hi);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8), key.Lo);
        return b;
    }

    private static TrafficDirection DetermineDirection(bool srcLocal, bool dstLocal)
    {
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
