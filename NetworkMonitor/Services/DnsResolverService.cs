using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace NetworkMonitor.Services;

public sealed class DnsResolverService : IDisposable
{
    private readonly ConcurrentDictionary<string, string> _cache = new();
    private readonly Channel<string> _queue;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task[] _workers;
    private readonly TimeSpan _lookupTimeout = TimeSpan.FromSeconds(2);

    public event EventHandler<DnsResolvedEventArgs>? Resolved;

    public DnsResolverService(int workerCount = 4)
    {
        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(8192)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = false,
            SingleWriter = false
        });
        _workers = new Task[workerCount];
        for (int i = 0; i < workerCount; i++)
            _workers[i] = Task.Run(WorkerLoop);
    }

    public string? Lookup(string ip)
        => _cache.TryGetValue(ip, out var h) ? h : null;

    public void Enqueue(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return;
        if (_cache.ContainsKey(ip)) return;
        if (IsUnresolvable(ip))
        {
            _cache[ip] = ip;
            return;
        }
        if (!_cache.TryAdd(ip, ip)) return;
        _queue.Writer.TryWrite(ip);
    }

    private async Task WorkerLoop()
    {
        var reader = _queue.Reader;
        try
        {
            while (await reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var ip))
                {
                    string host = ip;
                    try
                    {
                        if (!IPAddress.TryParse(ip, out _)) continue;
                        using var lookupCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                        lookupCts.CancelAfter(_lookupTimeout);
                        var entry = await Dns.GetHostEntryAsync(ip, lookupCts.Token).ConfigureAwait(false);
                        if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != ip)
                            host = entry.HostName;
                    }
                    catch
                    {
                    }
                    _cache[ip] = host;
                    if (host != ip)
                    {
                        try { Resolved?.Invoke(this, new DnsResolvedEventArgs(ip, host)); }
                        catch { }
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private static bool IsUnresolvable(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return true;
        if (ip == "0.0.0.0" || ip == "::") return true;
        if (ip == "255.255.255.255") return true;
        if (ip.StartsWith("224.") || ip.StartsWith("239.")) return true;
        if (ip.StartsWith("ff", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _queue.Writer.TryComplete();
        try { Task.WaitAll(_workers, TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}

public sealed class DnsResolvedEventArgs : EventArgs
{
    public string Ip { get; }
    public string Host { get; }
    public DnsResolvedEventArgs(string ip, string host) { Ip = ip; Host = host; }
}
