using System;

namespace NetworkMonitor.Models;

public enum ShareEventKind
{
    /// <summary>Подключение клиента к шаре (сессия).</summary>
    Session,
    /// <summary>Файл сейчас открыт удалённым клиентом (живой опрос SMB).</summary>
    OpenFile,
    /// <summary>Запрос доступа к файлу/папке (журнал безопасности, 5145).</summary>
    FileAccess,
    /// <summary>Неудачная сетевая авторизация (4625).</summary>
    LogonFailed
}

public sealed class ShareAccessEvent
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public ShareEventKind Kind { get; init; }
    public string Client { get; init; } = string.Empty;
    public string ClientPort { get; init; } = string.Empty;
    public string User { get; init; } = string.Empty;
    public string Share { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public string Access { get; init; } = string.Empty;
    public bool Denied { get; init; }
    /// <summary>Источник данных: «Сессия», «Открыт», «Аудит».</summary>
    public string Source { get; init; } = string.Empty;
    /// <summary>Для подключений через loopback — процесс туннеля (ssh.exe и т.п.).</summary>
    public string Via { get; init; } = string.Empty;
    public bool IsTunnel => !string.IsNullOrEmpty(Via);

    public string TimeText => Timestamp.ToString("HH:mm:ss");
    public string ResultText => Denied ? "ОТКАЗ" : "OK";
    public string KindText => Kind switch
    {
        ShareEventKind.Session => "Подключение",
        ShareEventKind.OpenFile => "Открыт файл",
        ShareEventKind.FileAccess => "Доступ к файлу",
        ShareEventKind.LogonFailed => "Ошибка входа",
        _ => Kind.ToString()
    };
    public string ClientText => string.IsNullOrEmpty(ClientPort) ? Client : $"{Client}:{ClientPort}";
}
