using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NetworkMonitor.Helpers;

internal static class NativeProcess
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, [Out] StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static string? TryGetImagePath(int pid)
    {
        if (pid <= 0) return null;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            // 32767 — предел длины пути NT; повтор нужен при включённых long paths
            foreach (var capacity in new[] { 1024, 32767 })
            {
                var sb = new StringBuilder(capacity);
                uint size = (uint)sb.Capacity;
                if (QueryFullProcessImageName(handle, 0, sb, ref size))
                    return sb.ToString(0, (int)size);
                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER) return null;
            }
            return null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    public static string? TryGetProcessName(int pid)
    {
        var path = TryGetImagePath(pid);
        if (string.IsNullOrEmpty(path)) return null;
        try { return Path.GetFileNameWithoutExtension(path); }
        catch { return null; }
    }
}
