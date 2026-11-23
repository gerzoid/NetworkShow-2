using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Microsoft.Data.Sqlite;
using NetworkMonitor.Models;

namespace NetworkMonitor.Services;

public sealed record HistoryFlowRow(string FirstSeen, string LastSeen, string Process, string Protocol, string AppProto, string Remote,
    string Host, string Alias, string Category, string Country, string Asn, long BytesIn, long BytesOut, long Packets, double RttMs, long Retransmits, long Resets)
{
    public long Bytes => BytesIn + BytesOut;
    public string Name => !string.IsNullOrEmpty(Alias) ? Alias : !string.IsNullOrEmpty(Host) ? Host : Remote;
    public string RttText => RttMs > 0 ? $"{RttMs:F0} мс" : string.Empty;
}

public sealed record HistoryEventRow(string Time, string Severity, string Title, string Message);

public sealed record NamedTotal(string Name, long Bytes, long Count);

/// <summary>Данные для отчёта за период.</summary>
public sealed class ReportData
{
    public DateTime From { get; init; }
    public DateTime To { get; init; }
    public long TotalIn, TotalOut;
    public int Flows;
    public List<NamedTotal> Processes { get; init; } = new();
    public List<NamedTotal> Sites { get; init; } = new();
    public List<NamedTotal> Countries { get; init; } = new();
    public List<NamedTotal> Categories { get; init; } = new();
    public List<NamedTotal> Protocols { get; init; } = new();
    public List<(string Name, double AvgRtt, double RetransPct, long Resets, long Flows)> Worst { get; init; } = new();
    public Dictionary<string, int> EventsBySeverity { get; init; } = new();
    public List<NamedTotal> TopEvents { get; init; } = new();
    public List<HistoryEventRow> Important { get; init; } = new();
    public int NewDevices;
}

/// <summary>
/// Долгая история в SQLite (C:\Users\gerz\AppData\Roaming\NetworkShow\history.db): соединения (потоки) и уведомления.
/// Потоки записываются периодически и при выходе (upsert по ключу), поэтому после перезапуска ничего не теряется;
/// по ним строятся поиск за любой период и недельный отчёт.
/// </summary>
public sealed class HistoryStore : IDisposable
{
    private const string TimeFmt = "yyyy-MM-dd HH:mm:ss";
    private readonly string _path;
    private readonly object _lock = new();
    private SqliteConnection? _db;

    public string DbPath => _path;

    public HistoryStore(string? path = null)
    {
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetworkShow", "history.db");
    }

    public bool IsOpen { get { lock (_lock) return _db is not null; } }

    public void Open()
    {
        lock (_lock)
        {
            if (_db is not null) return;
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            _db = new SqliteConnection($"Data Source={_path};Pooling=False");
            _db.Open();
            Exec("PRAGMA journal_mode=WAL;");
            Exec("PRAGMA synchronous=NORMAL;");
            Exec("CREATE TABLE IF NOT EXISTS flows(key TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, protocol TEXT, process TEXT, remote_ip TEXT, remote_port INTEGER, " +
                 "host TEXT, alias TEXT, app_proto TEXT, category TEXT, country TEXT, asn TEXT, bytes_in INTEGER, bytes_out INTEGER, packets INTEGER, rtt_ms REAL, retransmits INTEGER, resets INTEGER)");
            Exec("CREATE INDEX IF NOT EXISTS ix_flows_last ON flows(last_seen)");
            Exec("CREATE INDEX IF NOT EXISTS ix_flows_proc ON flows(process)");
            Exec("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, severity TEXT, title TEXT, message TEXT)");
            Exec("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts)");
        }
    }

    // ───────────── Запись ─────────────

    /// <summary>Сохраняет (upsert) потоки с трафиком. Использует живые счётчики, поэтому UI-поток не нужен.</summary>
    public void SaveFlows(IEnumerable<ConnectionAggregate> conns)
    {
        lock (_lock)
        {
            if (_db is null) return;
            using var tx = _db.BeginTransaction();
            using var cmd = _db.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO flows(key,first_seen,last_seen,protocol,process,remote_ip,remote_port,host,alias,app_proto,category,country,asn,bytes_in,bytes_out,packets,rtt_ms,retransmits,resets) " +
                "VALUES($key,$fs,$ls,$proto,$proc,$rip,$rport,$host,$alias,$app,$cat,$cc,$asn,$bi,$bo,$pk,$rtt,$re,$rs) " +
                "ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen, process=excluded.process, host=excluded.host, alias=excluded.alias, app_proto=excluded.app_proto, " +
                "category=excluded.category, country=excluded.country, asn=excluded.asn, bytes_in=excluded.bytes_in, bytes_out=excluded.bytes_out, packets=excluded.packets, " +
                "rtt_ms=excluded.rtt_ms, retransmits=excluded.retransmits, resets=excluded.resets";
            var p = new Dictionary<string, SqliteParameter>();
            foreach (var n in new[] { "$key", "$fs", "$ls", "$proto", "$proc", "$rip", "$rport", "$host", "$alias", "$app", "$cat", "$cc", "$asn", "$bi", "$bo", "$pk", "$rtt", "$re", "$rs" })
                p[n] = cmd.Parameters.Add(n, SqliteType.Text);
            foreach (var c in conns)
            {
                if (c.LiveBytes <= 0) continue;
                p["$key"].Value = c.Key + "|" + c.FirstSeen.Ticks.ToString(CultureInfo.InvariantCulture);
                p["$fs"].Value = c.FirstSeen.ToString(TimeFmt, CultureInfo.InvariantCulture);
                p["$ls"].Value = c.LiveLastSeen.ToString(TimeFmt, CultureInfo.InvariantCulture);
                p["$proto"].Value = c.Protocol;
                p["$proc"].Value = string.IsNullOrEmpty(c.ProcessName) ? "unknown" : c.ProcessName;
                p["$rip"].Value = c.RemoteIp;
                p["$rport"].Value = c.RemotePort;
                p["$host"].Value = c.SniOrHost;
                p["$alias"].Value = c.Alias;
                p["$app"].Value = c.AppProto;
                p["$cat"].Value = c.Category;
                p["$cc"].Value = c.Country;
                p["$asn"].Value = c.AsnText;
                p["$bi"].Value = c.LiveBytesIn;
                p["$bo"].Value = c.LiveBytesOut;
                p["$pk"].Value = c.LivePackets;
                p["$rtt"].Value = c.LiveRttMs;
                p["$re"].Value = c.LiveRetransmits;
                p["$rs"].Value = c.LiveResets;
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    public void SaveEvent(TrafficNotification n)
    {
        lock (_lock)
        {
            if (_db is null) return;
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "INSERT INTO events(ts,severity,title,message) VALUES($ts,$sev,$t,$m)";
            cmd.Parameters.AddWithValue("$ts", n.Timestamp.ToString(TimeFmt, CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$sev", n.Severity.ToString());
            cmd.Parameters.AddWithValue("$t", n.Title);
            cmd.Parameters.AddWithValue("$m", n.Message);
            cmd.ExecuteNonQuery();
        }
    }

    // ───────────── Чтение ─────────────

    public List<HistoryFlowRow> QueryFlows(DateTime from, string? text, int limit = 2000)
    {
        var list = new List<HistoryFlowRow>();
        lock (_lock)
        {
            if (_db is null) return list;
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT first_seen,last_seen,process,protocol,app_proto,remote_ip||':'||remote_port,host,alias,category,country,asn,bytes_in,bytes_out,packets,rtt_ms,retransmits,resets " +
                "FROM flows WHERE last_seen >= $from AND ($q IS NULL OR process LIKE $q OR remote_ip LIKE $q OR host LIKE $q OR alias LIKE $q OR category LIKE $q OR country LIKE $q OR asn LIKE $q OR app_proto LIKE $q) " +
                "ORDER BY last_seen DESC LIMIT $limit";
            cmd.Parameters.AddWithValue("$from", from.ToString(TimeFmt, CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$q", string.IsNullOrWhiteSpace(text) ? DBNull.Value : "%" + text.Trim() + "%");
            cmd.Parameters.AddWithValue("$limit", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read())
                list.Add(new HistoryFlowRow(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), Str(r, 4), r.GetString(5),
                    Str(r, 6), Str(r, 7), Str(r, 8), Str(r, 9), Str(r, 10), r.GetInt64(11), r.GetInt64(12), r.GetInt64(13), r.GetDouble(14), r.GetInt64(15), r.GetInt64(16)));
        }
        return list;
    }

    public List<HistoryEventRow> QueryEvents(DateTime from, string? text, int limit = 2000)
    {
        var list = new List<HistoryEventRow>();
        lock (_lock)
        {
            if (_db is null) return list;
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT ts,severity,title,message FROM events WHERE ts >= $from AND ($q IS NULL OR title LIKE $q OR message LIKE $q OR severity LIKE $q) ORDER BY ts DESC LIMIT $limit";
            cmd.Parameters.AddWithValue("$from", from.ToString(TimeFmt, CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("$q", string.IsNullOrWhiteSpace(text) ? DBNull.Value : "%" + text.Trim() + "%");
            cmd.Parameters.AddWithValue("$limit", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(new HistoryEventRow(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)));
        }
        return list;
    }

    public ReportData BuildReport(DateTime from, DateTime to)
    {
        var f = from.ToString(TimeFmt, CultureInfo.InvariantCulture);
        var t = to.ToString(TimeFmt, CultureInfo.InvariantCulture);
        const string site = "CASE WHEN length(alias)>0 THEN alias WHEN length(host)>0 THEN host ELSE remote_ip END";
        lock (_lock)
        {
            var data = new ReportData { From = from, To = to };
            if (_db is null) return data;

            using (var c = Cmd("SELECT COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM flows WHERE last_seen BETWEEN $f AND $t", f, t))
            using (var r = c.ExecuteReader())
                if (r.Read()) { data.Flows = r.GetInt32(0); data.TotalIn = r.GetInt64(1); data.TotalOut = r.GetInt64(2); }

            Fill(data.Processes, "process", f, t, 10);
            Fill(data.Sites, site, f, t, 15);
            Fill(data.Countries, "CASE WHEN length(country)=0 THEN '(локальная сеть / неизвестно)' ELSE country END", f, t, 10);
            Fill(data.Categories, "CASE WHEN length(category)=0 THEN '(без категории)' ELSE category END", f, t, 10);
            Fill(data.Protocols, "CASE WHEN length(app_proto)>0 THEN app_proto ELSE protocol END", f, t, 10);

            using (var c = Cmd("SELECT " + site + " n, AVG(CASE WHEN rtt_ms>0 THEN rtt_ms END), 100.0*SUM(retransmits)/MAX(SUM(packets),1), SUM(resets), COUNT(*) FROM flows " +
                               "WHERE last_seen BETWEEN $f AND $t AND protocol='TCP' AND packets>=50 GROUP BY n HAVING SUM(retransmits)>0 OR SUM(resets)>0 ORDER BY 3 DESC LIMIT 8", f, t))
            using (var r = c.ExecuteReader())
                while (r.Read()) data.Worst.Add((r.GetString(0), r.IsDBNull(1) ? 0 : r.GetDouble(1), r.GetDouble(2), r.GetInt64(3), r.GetInt64(4)));

            using (var c = Cmd("SELECT severity, COUNT(*) FROM events WHERE ts BETWEEN $f AND $t GROUP BY severity", f, t))
            using (var r = c.ExecuteReader())
                while (r.Read()) data.EventsBySeverity[r.GetString(0)] = r.GetInt32(1);

            using (var c = Cmd("SELECT title, COUNT(*) FROM events WHERE ts BETWEEN $f AND $t AND severity<>'Info' GROUP BY title ORDER BY 2 DESC LIMIT 12", f, t))
            using (var r = c.ExecuteReader())
                while (r.Read()) data.TopEvents.Add(new NamedTotal(r.GetString(0), 0, r.GetInt64(1)));

            using (var c = Cmd("SELECT ts,severity,title,message FROM events WHERE ts BETWEEN $f AND $t AND severity IN ('Critical','Warning') ORDER BY CASE severity WHEN 'Critical' THEN 0 ELSE 1 END, ts DESC LIMIT 40", f, t))
            using (var r = c.ExecuteReader())
                while (r.Read()) data.Important.Add(new HistoryEventRow(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)));

            using (var c = Cmd("SELECT COUNT(*) FROM events WHERE ts BETWEEN $f AND $t AND title='Новое устройство в сети'", f, t))
                data.NewDevices = Convert.ToInt32(c.ExecuteScalar(), CultureInfo.InvariantCulture);
            return data;
        }
    }

    private void Fill(List<NamedTotal> target, string expr, string f, string t, int limit)
    {
        using var c = Cmd($"SELECT {expr} n, SUM(bytes_in+bytes_out) b, COUNT(*) FROM flows WHERE last_seen BETWEEN $f AND $t GROUP BY n ORDER BY b DESC LIMIT {limit}", f, t);
        using var r = c.ExecuteReader();
        while (r.Read()) target.Add(new NamedTotal(r.IsDBNull(0) ? "?" : r.GetString(0), r.GetInt64(1), r.GetInt64(2)));
    }

    private SqliteCommand Cmd(string sql, string f, string t)
    {
        var c = _db!.CreateCommand();
        c.CommandText = sql;
        c.Parameters.AddWithValue("$f", f);
        c.Parameters.AddWithValue("$t", t);
        return c;
    }

    // ───────────── Обслуживание ─────────────

    public (long Flows, long Events) CountOlderThan(DateTime? cutoff)
    {
        lock (_lock)
        {
            if (_db is null) return (0, 0);
            var s = (cutoff ?? DateTime.MaxValue).ToString(TimeFmt, CultureInfo.InvariantCulture);
            return (Scalar("SELECT COUNT(*) FROM flows WHERE last_seen < $c", s), Scalar("SELECT COUNT(*) FROM events WHERE ts < $c", s));
        }
    }

    /// <summary>Удаляет записи старше границы; null — всё.</summary>
    public (long Flows, long Events) Purge(DateTime? olderThan)
    {
        lock (_lock)
        {
            if (_db is null) return (0, 0);
            var s = (olderThan ?? DateTime.MaxValue).ToString(TimeFmt, CultureInfo.InvariantCulture);
            long f = ExecCount("DELETE FROM flows WHERE last_seen < $c", s);
            long e = ExecCount("DELETE FROM events WHERE ts < $c", s);
            if (f + e > 1000) Exec("VACUUM");
            return (f, e);
        }
    }

    private long Scalar(string sql, string cutoff)
    {
        using var c = _db!.CreateCommand();
        c.CommandText = sql;
        c.Parameters.AddWithValue("$c", cutoff);
        return Convert.ToInt64(c.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private long ExecCount(string sql, string cutoff)
    {
        using var c = _db!.CreateCommand();
        c.CommandText = sql;
        c.Parameters.AddWithValue("$c", cutoff);
        return c.ExecuteNonQuery();
    }

    private void Exec(string sql)
    {
        using var c = _db!.CreateCommand();
        c.CommandText = sql;
        c.ExecuteNonQuery();
    }

    private static string Str(SqliteDataReader r, int i) => r.IsDBNull(i) ? string.Empty : r.GetString(i);

    public void Dispose()
    {
        lock (_lock)
        {
            _db?.Dispose();
            _db = null;
        }
    }
}
