using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using NetworkMonitor.Helpers;

namespace NetworkMonitor.Services;

/// <summary>Недельный отчёт «что происходило в сети»: самодостаточный HTML-файл (открывается в браузере, можно печатать в PDF).</summary>
public static class ReportService
{
    public static string BuildHtml(ReportData d)
    {
        string E(string s) => WebUtility.HtmlEncode(s ?? string.Empty);
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><title>Отчёт NetworkShow</title><style>")
          .Append("body{font:14px/1.45 Segoe UI,Arial,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1b1b1f}")
          .Append("h1{font-size:22px;margin-bottom:2px}h2{font-size:16px;margin:26px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}")
          .Append("table{border-collapse:collapse;width:100%;margin:6px 0}th,td{padding:5px 8px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}")
          .Append("th{background:#f4f5f7}td.n,th.n{text-align:right;white-space:nowrap}.kpi{display:flex;gap:12px;flex-wrap:wrap}")
          .Append(".kpi div{background:#f4f5f7;border-radius:8px;padding:10px 16px}.kpi b{display:block;font-size:20px}")
          .Append(".c{color:#c62828;font-weight:600}.w{color:#b26a00;font-weight:600}.m{color:#777}.bar{background:#3d7dd9;height:8px;border-radius:4px}")
          .Append("</style></head><body>");
        sb.Append($"<h1>Отчёт о сети</h1><div class=\"m\">{d.From:dd.MM.yyyy HH:mm} — {d.To:dd.MM.yyyy HH:mm} · сформирован {DateTime.Now:dd.MM.yyyy HH:mm}</div>");

        int crit = d.EventsBySeverity.GetValueOrDefault("Critical"), warn = d.EventsBySeverity.GetValueOrDefault("Warning"), info = d.EventsBySeverity.GetValueOrDefault("Info");
        sb.Append("<div class=\"kpi\" style=\"margin-top:14px\">")
          .Append($"<div><b>↓ {ByteFormatter.Format(d.TotalIn)}</b>получено</div><div><b>↑ {ByteFormatter.Format(d.TotalOut)}</b>отправлено</div>")
          .Append($"<div><b>{d.Flows:N0}</b>соединений</div><div><b class=\"c\">{crit}</b>критичных</div><div><b class=\"w\">{warn}</b>предупреждений</div>")
          .Append($"<div><b>{info}</b>информационных</div><div><b>{d.NewDevices}</b>новых устройств</div></div>");

        long total = d.TotalIn + d.TotalOut;
        Table(sb, "Процессы по объёму", d.Processes, E, total);
        Table(sb, "Сайты и адреса по объёму", d.Sites, E, total);
        Table(sb, "Категории трафика", d.Categories, E, total);
        Table(sb, "Страны", d.Countries, E, total);
        Table(sb, "Протоколы (по содержимому, если определены)", d.Protocols, E, total);

        sb.Append("<h2>Качество связи: где хуже всего</h2>");
        if (d.Worst.Count == 0) sb.Append("<div class=\"m\">Заметных повторных передач и сбросов не зафиксировано.</div>");
        else
        {
            sb.Append("<table><tr><th>Адрес</th><th class=\"n\">Средний RTT</th><th class=\"n\">Повторы пакетов</th><th class=\"n\">Сбросы (RST)</th><th class=\"n\">Соединений</th></tr>");
            foreach (var w in d.Worst)
                sb.Append($"<tr><td>{E(w.Name)}</td><td class=\"n\">{(w.AvgRtt > 0 ? w.AvgRtt.ToString("F0", CultureInfo.InvariantCulture) + " мс" : "—")}</td><td class=\"n\">{w.RetransPct:F1} %</td><td class=\"n\">{w.Resets}</td><td class=\"n\">{w.Flows}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("<h2>События безопасности</h2>");
        if (d.TopEvents.Count > 0)
        {
            sb.Append("<table><tr><th>Тип</th><th class=\"n\">Сколько раз</th></tr>");
            foreach (var e in d.TopEvents) sb.Append($"<tr><td>{E(e.Name)}</td><td class=\"n\">{e.Count}</td></tr>");
            sb.Append("</table>");
        }
        if (d.Important.Count == 0) sb.Append("<div class=\"m\">Критичных и предупреждающих событий нет.</div>");
        else
        {
            sb.Append("<table><tr><th>Время</th><th>Уровень</th><th>Событие</th></tr>");
            foreach (var e in d.Important)
                sb.Append($"<tr><td class=\"n\">{E(e.Time)}</td><td class=\"{(e.Severity == "Critical" ? "c" : "w")}\">{(e.Severity == "Critical" ? "Критично" : "Предупреждение")}</td><td><b>{E(e.Title)}</b><br><span class=\"m\">{E(e.Message)}</span></td></tr>");
            sb.Append("</table>");
        }
        sb.Append("<p class=\"m\" style=\"margin-top:28px\">Страны и провайдеры — по базе IP-to-Country/ASN Lite от <a href=\"https://db-ip.com\">DB-IP.com</a> (CC BY 4.0). Категории сайтов и типы устройств определяются эвристически и могут ошибаться.</p></body></html>");
        return sb.ToString();
    }

    private static void Table(StringBuilder sb, string title, List<NamedTotal> rows, Func<string, string> e, long total)
    {
        sb.Append($"<h2>{e(title)}</h2>");
        if (rows.Count == 0) { sb.Append("<div class=\"m\">Нет данных за период.</div>"); return; }
        long max = Math.Max(1, rows.Max(r => r.Bytes));
        sb.Append("<table><tr><th>Название</th><th class=\"n\">Объём</th><th class=\"n\">Доля</th><th style=\"width:30%\"></th><th class=\"n\">Соед.</th></tr>");
        foreach (var r in rows)
        {
            double share = total > 0 ? 100.0 * r.Bytes / total : 0;
            sb.Append($"<tr><td>{e(r.Name)}</td><td class=\"n\">{ByteFormatter.Format(r.Bytes)}</td><td class=\"n\">{share:F1} %</td>" +
                      $"<td><div class=\"bar\" style=\"width:{(100.0 * r.Bytes / max).ToString("F0", CultureInfo.InvariantCulture)}%\"></div></td><td class=\"n\">{r.Count}</td></tr>");
        }
        sb.Append("</table>");
    }

    public static string DefaultDir => Path.Combine(AppContext.BaseDirectory, "logs", "reports");

    public static string Save(ReportData d, string? dir = null)
    {
        dir ??= DefaultDir;
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"report_{d.To:yyyyMMdd_HHmm}.html");
        File.WriteAllText(path, BuildHtml(d), new UTF8Encoding(true));
        return path;
    }
}
