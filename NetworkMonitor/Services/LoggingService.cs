using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

public enum LogFormat
{
    Json,
    Csv
}

public sealed class LoggingService : IDisposable
{
    private readonly object _lock = new();
    private readonly string _logDir;
    private readonly long _maxBytes;
    private LogFormat _format;
    private StreamWriter? _writer;
    private string? _currentPath;
    private bool _csvHeaderWritten;

    public LogFormat Format
    {
        get => _format;
        set
        {
            if (_format == value) return;
            lock (_lock)
            {
                Close();
                _format = value;
                _csvHeaderWritten = false;
            }
        }
    }

    public string LogDirectory => _logDir;

    public LoggingService(string? directory = null, LogFormat format = LogFormat.Json, long maxBytes = 5 * 1024 * 1024)
    {
        _logDir = directory ?? Path.Combine(AppContext.BaseDirectory, "logs");
        Directory.CreateDirectory(_logDir);
        _format = format;
        _maxBytes = maxBytes;
    }

    public void Write(PacketRecord r)
    {
        lock (_lock)
        {
            EnsureWriter();
            if (_writer is null) return;
            if (_format == LogFormat.Json)
            {
                _writer.WriteLine(JsonSerializer.Serialize(new
                {
                    ts = r.Timestamp,
                    src = r.SourceIp,
                    dst = r.DestinationIp,
                    sport = r.SourcePort,
                    dport = r.DestinationPort,
                    proto = r.Protocol,
                    size = r.Size,
                    process = r.ProcessName,
                    pid = r.ProcessId,
                    dir = r.Direction.ToString()
                }));
            }
            else
            {
                if (!_csvHeaderWritten)
                {
                    _writer.WriteLine("timestamp,source_ip,destination_ip,source_port,destination_port,protocol,size,process,pid,direction");
                    _csvHeaderWritten = true;
                }
                _writer.WriteLine(string.Join(',', new[]
                {
                    r.Timestamp.ToString("O", CultureInfo.InvariantCulture),
                    r.SourceIp,
                    r.DestinationIp,
                    r.SourcePort.ToString(CultureInfo.InvariantCulture),
                    r.DestinationPort.ToString(CultureInfo.InvariantCulture),
                    r.Protocol,
                    r.Size.ToString(CultureInfo.InvariantCulture),
                    Escape(r.ProcessName),
                    r.ProcessId.ToString(CultureInfo.InvariantCulture),
                    r.Direction.ToString()
                }));
            }

            if (_writer.BaseStream.Length >= _maxBytes)
                Rotate();
        }
    }

    public void WriteNotification(TrafficNotification n)
    {
        lock (_lock)
        {
            try
            {
                var path = Path.Combine(_logDir, "notifications.log");
                File.AppendAllText(path, $"[{n.Timestamp:O}] [{n.Severity}] {n.Title}: {n.Message}{Environment.NewLine}", Encoding.UTF8);
            }
            catch { }
        }
    }

    public string ExportConnections(IEnumerable<ConnectionAggregate> connections, LogFormat format)
    {
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var ext = format == LogFormat.Json ? "json" : "csv";
        var path = Path.Combine(_logDir, $"connections_{stamp}.{ext}");
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        using var sw = new StreamWriter(fs, Encoding.UTF8);
        if (format == LogFormat.Json)
        {
            sw.WriteLine("[");
            bool first = true;
            foreach (var c in connections)
            {
                if (!first) sw.WriteLine(",");
                sw.Write(JsonSerializer.Serialize(new
                {
                    proto = c.Protocol,
                    service = c.Service,
                    app = c.AppLabel,
                    scope = c.ScopeText,
                    sni = c.Sni,
                    local_ip = c.LocalIp,
                    local_port = c.LocalPort,
                    remote_ip = c.RemoteIp,
                    remote_port = c.RemotePort,
                    remote_host = c.RemoteHost,
                    process = c.ProcessName,
                    packets = c.Packets,
                    bytes = c.Bytes,
                    bytes_in = c.BytesIn,
                    bytes_out = c.BytesOut,
                    first_seen = c.FirstSeen,
                    last_seen = c.LastSeen
                }));
                first = false;
            }
            sw.WriteLine();
            sw.WriteLine("]");
        }
        else
        {
            sw.WriteLine("protocol,service,app,scope,sni,local_ip,local_port,remote_ip,remote_port,remote_host,process,packets,bytes,bytes_in,bytes_out,first_seen,last_seen");
            foreach (var c in connections)
            {
                sw.WriteLine(string.Join(',', new[]
                {
                    c.Protocol,
                    Escape(c.Service),
                    Escape(c.AppLabel),
                    c.ScopeText,
                    Escape(c.Sni),
                    c.LocalIp,
                    c.LocalPort.ToString(CultureInfo.InvariantCulture),
                    c.RemoteIp,
                    c.RemotePort.ToString(CultureInfo.InvariantCulture),
                    Escape(c.RemoteHost),
                    Escape(c.ProcessName),
                    c.Packets.ToString(CultureInfo.InvariantCulture),
                    c.Bytes.ToString(CultureInfo.InvariantCulture),
                    c.BytesIn.ToString(CultureInfo.InvariantCulture),
                    c.BytesOut.ToString(CultureInfo.InvariantCulture),
                    c.FirstSeen.ToString("O", CultureInfo.InvariantCulture),
                    c.LastSeen.ToString("O", CultureInfo.InvariantCulture)
                }));
            }
        }
        return path;
    }

    private void EnsureWriter()
    {
        if (_writer is not null) return;
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var ext = _format == LogFormat.Json ? "jsonl" : "csv";
        _currentPath = Path.Combine(_logDir, $"traffic_{stamp}.{ext}");
        var fs = new FileStream(_currentPath, FileMode.Append, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(fs, new UTF8Encoding(false)) { AutoFlush = false };
    }

    private void Rotate()
    {
        Close();
        EnsureWriter();
    }

    private void Close()
    {
        if (_writer is not null)
        {
            try { _writer.Flush(); } catch { }
            _writer.Dispose();
            _writer = null;
        }
        _csvHeaderWritten = false;
    }

    public void Flush()
    {
        lock (_lock)
        {
            try { _writer?.Flush(); } catch { }
        }
    }

    private static string Escape(string s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    public void Dispose()
    {
        lock (_lock) Close();
    }
}
