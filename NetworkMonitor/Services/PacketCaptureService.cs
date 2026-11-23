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
    private const int SnapLength = 2048;
    private readonly Dictionary<IpKey, IpInfo> _ipCache = new();

    // Имена протоколов (кроме TCP/UDP) как у PacketDotNet, без Enum.ToString() на каждый пакет
    private static readonly string[] ProtocolNames = Enumerable.Range(0, 256)
        .Select(i => ((ProtocolType)i).ToString()).ToArray();

    public ChannelReader<PacketRecord> Reader => _channel.Reader;
    public bool IsRunning { get; private set; }

    private volatile bool _extractSites;
    /// <summary>Извлекать SNI (TLS/QUIC). Выключено по умолчанию — домены не читаются, пока пользователь не включит.</summary>
    public bool ExtractSites { get => _extractSites; set => _extractSites = value; }

    private volatile bool _parseDeviceHints;
    /// <summary>Разбирать DHCP/mDNS/SSDP для определения типа устройств в сети (событие <see cref="DeviceHintFound"/>).</summary>
    public bool ParseDeviceHints { get => _parseDeviceHints; set => _parseDeviceHints = value; }

    public event Action<DeviceHint>? DeviceHintFound;
    public event Action<ArpFrame>? ArpFrameSeen;
    public event Action<DhcpServerMessage>? DhcpServerSeen;
    public event Action<NameResponse>? NameResponseSeen;

    private volatile bool _parseDnsPackets = true;
    /// <summary>Разбирать DNS-запросы из пакетов (false, пока работает ETW-мониторинг DNS — он точнее и даёт процесс).</summary>
    public bool ParseDnsPackets { get => _parseDnsPackets; set => _parseDnsPackets = value; }
    public long DroppedPackets => Interlocked.Read(ref _droppedPackets);

    /// <summary>Пакеты, потерянные самим драйвером/буфером Npcap (приложение не успело их забрать).</summary>
    public long DriverDroppedPackets
    {
        get
        {
            try
            {
                var st = _device?.Statistics;
                return st is null ? 0 : (long)st.DroppedPackets + st.InterfaceDroppedPackets;
            }
            catch { return 0; }
        }
    }

    public event EventHandler<string>? CaptureError;

    public PacketCaptureService(ProcessResolverService processResolver)
    {
        _processResolver = processResolver;
        // DropOldest: TryWrite при переполнении всегда true, поэтому потери считаем в itemDropped
        _channel = Channel.CreateBounded<PacketRecord>(new BoundedChannelOptions(50_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true
        }, _ => Interlocked.Increment(ref _droppedPackets));
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

                var info = new NetworkInterfaceInfo
                {
                    Name = dev.Name,
                    Description = dev.Description ?? string.Empty,
                    FriendlyName = friendly
                };
                InterfaceProbe.Fill(info);
                result.Add(info);
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
                BufferSize = 16 * 1024 * 1024,
                // Заголовки + ClientHello/QUIC Initial умещаются в 2048 байт; остальное копировать не нужно
                Snaplen = SnapLength
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
            if (!PacketHeaderParser.TryParse(_linkType, data, out var h))
            {
                // Не IP: ARP нужен детектору атак в локальной сети
                if (_parseDeviceHints && _linkType == 1 && LanFrameParser.TryParseArp(data, out var arp)) ArpFrameSeen?.Invoke(arp);
                return;
            }

            string protocol;
            string? sni = null;
            string? dnsName = null;
            string? appProto = null;
            string? ja3 = null;
            bool wantHints = false;
            var payload = h.PayloadLength > 0 ? data.Slice(h.PayloadOffset, h.PayloadLength) : default;
            if (payload.Length >= 4 && (h.IsTcp || h.IsUdp))
            {
                appProto = ProtocolSniffer.Detect(h.IsTcp, h.SourcePort, h.DestinationPort, payload);
                if (h.IsTcp && ReferenceEquals(appProto, ProtocolSniffer.Tls) && payload[5] == 0x01 &&
                    Ja3Fingerprint.TryCompute(payload, out var j3, out _)) ja3 = j3;
            }
            if (h.IsTcp)
            {
                protocol = "TCP";
                if (_extractSites && payload.Length >= 43 && payload[0] == 0x16 && payload[5] == 0x01)
                    sni = TlsSniExtractor.TryExtract(payload);
            }
            else if (h.IsUdp)
            {
                protocol = "UDP";
                if (_parseDeviceHints && DeviceHintParser.IsCandidate(h.SourcePort, h.DestinationPort)) wantHints = true;
                if (_extractSites && _parseDnsPackets && h.DestinationPort == 53 && payload.Length > 16)
                    DnsQueryParser.TryParse(payload, out dnsName, out _);
                // HTTP/3: SNI из QUIC Initial (только исходящие ClientHello на 443,
                // длинный заголовок типа Initial и датаграмма >= 1200 — дешёвый фильтр до криптографии)
                if (_extractSites && h.DestinationPort == 443 && payload.Length >= 1200 && (payload[0] & 0xF0) == 0xC0)
                    sni = QuicSniExtractor.TryExtract(payload.ToArray());
            }
            else
            {
                protocol = ProtocolNames[h.Protocol];
            }

            var src = GetIpInfo(h.Source, data, isSource: true);
            if (_parseDeviceHints && h.IsUdp && payload.Length > 16)
            {
                if (h.SourcePort == 67 && h.DestinationPort == 68 && LanFrameParser.TryParseDhcpServer(payload, src.Text, out var dhcp)) DhcpServerSeen?.Invoke(dhcp);
                else if ((h.SourcePort == 5355 || h.SourcePort == 137) && LanFrameParser.TryParseNameResponse(h.SourcePort, payload, src.Text, out var nr)) NameResponseSeen?.Invoke(nr);
            }
            if (wantHints)
                foreach (var hint in DeviceHintParser.Parse(h.SourcePort, h.DestinationPort, payload, src.Text))
                    DeviceHintFound?.Invoke(hint);
            var dst = GetIpInfo(h.Destination, data, isSource: false);
            var direction = DetermineDirection(src.IsLocal, dst.IsLocal);

            Emit(e.Header.Timeval, src.Text, h.SourcePort, dst.Text, h.DestinationPort,
                protocol, OriginalLength(e), direction, sni, h.TcpFlags, dnsName, h.TcpSeq, payload.Length, appProto, ja3);
        }
        catch
        {
            Interlocked.Increment(ref _droppedPackets);
        }
    }

    // При snaplen данные обрезаны — размер для статистики берём из исходной длины кадра
    private static int OriginalLength(PacketCapture e)
    {
        var len = e.Header is PcapHeader ph ? (int)ph.PacketLength : 0;
        return len > 0 ? len : e.Data.Length;
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
        byte flags = 0;

        var tcp = packet.Extract<TcpPacket>();
        var udp = packet.Extract<UdpPacket>();
        if (tcp is not null)
        {
            srcPort = tcp.SourcePort;
            dstPort = tcp.DestinationPort;
            protocol = "TCP";
            flags = (byte)((tcp.Synchronize ? 0x02 : 0) | (tcp.Acknowledgment ? 0x10 : 0)
                           | (tcp.Reset ? 0x04 : 0) | (tcp.Finished ? 0x01 : 0));

            var payload = tcp.PayloadData;
            if (_extractSites && payload is { Length: >= 43 } && payload[0] == 0x16 && payload[5] == 0x01)
                sni = TlsSniExtractor.TryExtract(payload);
        }
        else if (udp is not null)
        {
            srcPort = udp.SourcePort;
            dstPort = udp.DestinationPort;
            protocol = "UDP";

            if (_extractSites && dstPort == 443)
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
            protocol, OriginalLength(e), direction, sni, flags);
    }

    private void Emit(PosixTimeval timeval, string srcIp, int srcPort, string dstIp, int dstPort,
        string protocol, int size, TrafficDirection direction, string? sni, byte tcpFlags = 0, string? dnsName = null,
        uint tcpSeq = 0, int payloadLength = 0, string? appProto = null, string? ja3 = null)
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
            Sni = sni,
            TcpFlags = tcpFlags,
            DnsName = dnsName,
            TcpSeq = tcpSeq,
            PayloadLength = payloadLength,
            AppProto = appProto,
            Ja3 = ja3
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
