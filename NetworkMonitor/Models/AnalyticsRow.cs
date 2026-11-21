using System;
using System.Collections.Generic;

namespace NetworkMonitor.Models;

/// <summary>Строка таблицы аналитики: группа соединений (протокол, сайт или процесс) с суммарными счётчиками.</summary>
public sealed class AnalyticsRow
{
    public string Name { get; init; } = string.Empty;
    /// <summary>Доп. сведения: процессы сайта / протоколы процесса.</summary>
    public string Extra { get; init; } = string.Empty;
    public int Connections { get; init; }
    public int Hosts { get; init; }
    public long Packets { get; init; }
    public long Bytes { get; init; }
    public long BytesIn { get; init; }
    public long BytesOut { get; init; }
    public double Share { get; init; }
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; init; }
    /// <summary>Соединения группы (по убыванию объёма, до 500) — для панели детализации.</summary>
    public IReadOnlyList<ConnectionAggregate> Items { get; init; } = Array.Empty<ConnectionAggregate>();

    public string ShareText => Share.ToString("P1");
}
