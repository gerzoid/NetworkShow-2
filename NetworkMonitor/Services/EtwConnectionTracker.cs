using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetworkMonitor.Services;

public sealed class EtwConnectionTracker : IDisposable
{
    private const string SessionName = "NetworkShow-KernelNet";

    private readonly ProcessResolverService _resolver;
    private TraceEventSession? _session;
    private Task? _processTask;
    private volatile bool _disposed;

    public bool IsRunning => _session is not null;
    public string? LastError { get; private set; }

    public EtwConnectionTracker(ProcessResolverService resolver)
    {
        _resolver = resolver;
    }

    public bool TryStart()
    {
        if (IsRunning) return true;
        try
        {
            try { TraceEventSession.GetActiveSession(SessionName)?.Stop(); } catch { }

            _session = new TraceEventSession(SessionName)
            {
                StopOnDispose = true
            };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            var kernel = _session.Source.Kernel;
            kernel.TcpIpSend += OnTcpSend;
            kernel.TcpIpRecv += OnTcpRecv;
            kernel.TcpIpSendIPV6 += OnTcpSendV6;
            kernel.TcpIpRecvIPV6 += OnTcpRecvV6;
            kernel.UdpIpSend += OnUdpSend;
            kernel.UdpIpRecv += OnUdpRecv;
            kernel.UdpIpSendIPV6 += OnUdpSendV6;
            kernel.UdpIpRecvIPV6 += OnUdpRecvV6;

            _processTask = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) { LastError = ex.Message; }
            });
            return true;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            try { _session?.Dispose(); } catch { }
            _session = null;
            return false;
        }
    }

    private void OnTcpSend(TcpIpSendTraceData d) => _resolver.Upsert("TCP", d.saddr.ToString(), d.sport, d.ProcessID);
    private void OnTcpRecv(TcpIpTraceData d) => _resolver.Upsert("TCP", d.daddr.ToString(), d.dport, d.ProcessID);
    private void OnTcpSendV6(TcpIpV6SendTraceData d) => _resolver.Upsert("TCP", d.saddr.ToString(), d.sport, d.ProcessID);
    private void OnTcpRecvV6(TcpIpV6TraceData d) => _resolver.Upsert("TCP", d.daddr.ToString(), d.dport, d.ProcessID);
    private void OnUdpSend(UdpIpTraceData d) => _resolver.Upsert("UDP", d.saddr.ToString(), d.sport, d.ProcessID);
    private void OnUdpRecv(UdpIpTraceData d) => _resolver.Upsert("UDP", d.daddr.ToString(), d.dport, d.ProcessID);
    private void OnUdpSendV6(UpdIpV6TraceData d) => _resolver.Upsert("UDP", d.saddr.ToString(), d.sport, d.ProcessID);
    private void OnUdpRecvV6(UpdIpV6TraceData d) => _resolver.Upsert("UDP", d.daddr.ToString(), d.dport, d.ProcessID);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _session?.Stop(); } catch { }
        // Дожидаемся Process(), чтобы обработчики не дёргали резолвер после его Dispose
        try { _processTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
