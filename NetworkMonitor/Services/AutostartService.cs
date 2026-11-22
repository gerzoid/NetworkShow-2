using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace NetworkMonitor.Services;

/// <summary>
/// Автозапуск вместе с Windows через планировщик заданий (триггер «при входе», наивысшие права).
/// Программа требует прав администратора, а запись в Run тихо не запускает такие программы — поэтому задание, а не реестр.
/// Создавать и удалять задание может только запущенная от администратора копия (манифест уже это требует).
/// </summary>
public static class AutostartService
{
    public const string TaskName = "NetworkShow";
    public const string Argument = "--autostart";

    public static bool IsEnabled() => RunSchtasks($"/Query /TN \"{TaskName}\"", out _) == 0;

    /// <summary>Создаёт или обновляет задание (путь к exe берётся у текущего процесса).</summary>
    public static (bool Ok, string Message) Enable()
    {
        try
        {
            var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Не удалось определить путь к программе.");
            var xml = BuildTaskXml(WindowsIdentity.GetCurrent().Name, exe);
            var tmp = Path.Combine(Path.GetTempPath(), $"networkshow-task-{Guid.NewGuid():N}.xml");
            File.WriteAllText(tmp, xml, Encoding.Unicode); // schtasks ожидает UTF-16
            try
            {
                int rc = RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{tmp}\" /F", out var output);
                return rc == 0 ? (true, "Автозапуск включён.") : (false, "Не удалось создать задание автозапуска: " + output.Trim());
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
        catch (Exception ex) { return (false, "Автозапуск: " + ex.Message); }
    }

    public static (bool Ok, string Message) Disable()
    {
        if (!IsEnabled()) return (true, "Автозапуск выключен.");
        int rc = RunSchtasks($"/Delete /TN \"{TaskName}\" /F", out var output);
        return rc == 0 ? (true, "Автозапуск выключен.") : (false, "Не удалось удалить задание автозапуска: " + output.Trim());
    }

    /// <summary>Приводит задание к желаемому состоянию: после переноса или обновления программы путь в задании мог устареть.</summary>
    public static void Reconcile(bool desired)
    {
        try
        {
            if (!desired) return;
            var exe = Environment.ProcessPath;
            bool ok = RunSchtasks($"/Query /TN \"{TaskName}\" /XML", out var xml) == 0 &&
                      exe is not null && xml.Contains(exe, StringComparison.OrdinalIgnoreCase);
            if (!ok) Enable();
        }
        catch { }
    }

    public static string BuildTaskXml(string user, string exePath)
    {
        string u = SecurityElement.Escape(user), e = SecurityElement.Escape(exePath);
        string dir = SecurityElement.Escape(Path.GetDirectoryName(exePath) ?? string.Empty);
        return $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>NetworkShow: мониторинг сети при входе в Windows</Description></RegistrationInfo>
              <Triggers>
                <LogonTrigger><Enabled>true</Enabled><UserId>{u}</UserId><Delay>PT15S</Delay></LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author"><UserId>{u}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>true</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec><Command>{e}</Command><Arguments>{Argument}</Arguments><WorkingDirectory>{dir}</WorkingDirectory></Exec>
              </Actions>
            </Task>
            """;
    }

    private static int RunSchtasks(string args, out string output)
    {
        output = string.Empty;
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            if (p is null) return -1;
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return -2; }
            output = stdout.Result + stderr.Result;
            return p.ExitCode;
        }
        catch (Exception ex)
        {
            output = ex.Message;
            return -1;
        }
    }
}
