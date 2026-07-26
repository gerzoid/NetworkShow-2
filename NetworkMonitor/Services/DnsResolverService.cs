using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace NetworkMonitor.Services;

public sealed class DnsResolverService : IDisposable
{
    private static readonly TimeSpan PositiveTtl = TimeSpan.FromHours(1);
    private static readonly TimeSpan NegativeTtl = TimeSpan.FromMinutes(5);

    // Host == null — неудачный lookup (негативная запись); Pending — в очереди на резолв
    private record struct CacheEntry(string? Host, DateTime CachedAt, bool Pending);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
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
    {
        if (!_cache.TryGetValue(ip, out var e)) return null;
        if (e.Pending || e.Host is null) return null;
        return DateTime.UtcNow - e.CachedAt < PositiveTtl ? e.Host : null;
    }

    public void Enqueue(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return;
        if (IsUnresolvable(ip)) return;

        if (_cache.TryGetValue(ip, out var e))
        {
            if (e.Pending) return;
            var ttl = e.Host is null ? NegativeTtl : PositiveTtl;
            if (DateTime.UtcNow - e.CachedAt < ttl) return;
        }

        _cache[ip] = new CacheEntry(null, DateTime.UtcNow, Pending: true);
        _queue.Writer.TryWrite(ip);
    }

    /// <summary>Удаляет устаревшие записи — кэш не растёт бесконечно на длинных сессиях.</summary>
    public void Prune()
    {
        var cutoff = DateTime.UtcNow - PositiveTtl - PositiveTtl;
        foreach (var kv in _cache)
        {
            if (!kv.Value.Pending && kv.Value.CachedAt < cutoff)
                _cache.TryRemove(kv.Key, out _);
        }
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
                    string? host = null;
                    try
                    {
                        if (!IPAddress.TryParse(ip, out _))
                        {
                            _cache.TryRemove(ip, out _);
                            continue;
                        }
                        using var lookupCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                        lookupCts.CancelAfter(_lookupTimeout);
                        var entry = await Dns.GetHostEntryAsync(ip, lookupCts.Token).ConfigureAwait(false);
                        if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != ip)
                            host = entry.HostName;
                    }
                    catch
                    {
                    }
                    _cache[ip] = new CacheEntry(host, DateTime.UtcNow, Pending: false);
                    if (host is not null)
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
        if (ip.StartsWith("169.254.")) return true;
        if (ip.StartsWith("ff", StringComparison.OrdinalIgnoreCase)) return true;
        // Multicast 224.0.0.0/4 — все октеты 224-239
        if (IPAddress.TryParse(ip, out var addr))
        {
            var b = addr.GetAddressBytes();
            if (b.Length == 4 && b[0] >= 224 && b[0] <= 239) return true;
        }
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
