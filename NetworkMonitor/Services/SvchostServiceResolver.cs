using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Management;
using System.Threading;

namespace NetworkMonitor.Services;

public sealed class SvchostServiceResolver : IDisposable
{
    private ConcurrentDictionary<int, IReadOnlyList<string>> _pidToServices = new();
    private readonly Timer _timer;
    private volatile bool _disposed;

    public SvchostServiceResolver()
    {
        Refresh();
        // Состав служб в svchost меняется редко — частый WMI-опрос не нужен
        _timer = new Timer(_ => Refresh(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public IReadOnlyList<string> GetServices(int pid)
    {
        if (_pidToServices.TryGetValue(pid, out var list)) return list;
        return Array.Empty<string>();
    }

    private void Refresh()
    {
        if (_disposed) return;
        var next = new ConcurrentDictionary<int, IReadOnlyList<string>>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name FROM Win32_Service WHERE State='Running' AND ProcessId<>0");
            using var results = searcher.Get();
            var temp = new Dictionary<int, List<string>>();
            foreach (var obj in results)
            {
                using (obj)
                {
                    int pid = 0;
                    try { pid = Convert.ToInt32(obj["ProcessId"]); } catch { }
                    var name = obj["Name"]?.ToString();
                    if (pid <= 0 || string.IsNullOrEmpty(name)) continue;
                    if (!temp.TryGetValue(pid, out var list))
                    {
                        list = new List<string>();
                        temp[pid] = list;
                    }
                    list.Add(name);
                }
            }
            foreach (var kv in temp)
            {
                kv.Value.Sort(StringComparer.OrdinalIgnoreCase);
                next[kv.Key] = kv.Value;
            }
            _pidToServices = next;
        }
        catch
        {
        }
    }

    public void Dispose()
    {
        _disposed = true;
        // Dispose(WaitHandle) дожидается выполняющегося коллбэка таймера
        using var wh = new ManualResetEvent(false);
        if (_timer.Dispose(wh)) wh.WaitOne(1000);
    }
}
