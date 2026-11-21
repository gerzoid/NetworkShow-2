using System;
using System.Runtime.InteropServices;

namespace NetworkMonitor.Helpers;

/// <summary>
/// Чтение/включение подкатегорий расширенной политики аудита через advapi32
/// (не зависит от локализации auditpol). Требуются права администратора.
/// </summary>
internal static class AuditPolicyHelper
{
    // Object Access → File Share / Detailed File Share
    public static readonly Guid FileShare = new("0CCE9224-69AE-11D9-BED3-505054503030");
    public static readonly Guid DetailedFileShare = new("0CCE9244-69AE-11D9-BED3-505054503030");
    // Logon/Logoff → Logon (для 4625)
    public static readonly Guid Logon = new("0CCE9215-69AE-11D9-BED3-505054503030");

    private const uint POLICY_AUDIT_EVENT_SUCCESS = 0x1;
    private const uint POLICY_AUDIT_EVENT_FAILURE = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditSetSystemPolicy([In] AUDIT_POLICY_INFORMATION[] pAuditPolicy, uint dwPolicyCount);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    /// <summary>Возвращает флаги аудита подкатегории (1 = успех, 2 = отказ) или null при ошибке.</summary>
    public static uint? Query(Guid subCategory)
    {
        try
        {
            if (!AuditQuerySystemPolicy(new[] { subCategory }, 1, out var ptr) || ptr == IntPtr.Zero)
                return null;
            try
            {
                var info = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(ptr);
                return info.AuditingInformation & 0x3;
            }
            finally { AuditFree(ptr); }
        }
        catch { return null; }
    }

    public static bool IsFullyEnabled(Guid subCategory) => Query(subCategory) == 3;

    /// <summary>Включает аудит успехов и отказов для подкатегории.</summary>
    public static bool EnableSuccessAndFailure(Guid subCategory)
    {
        try
        {
            var info = new[]
            {
                new AUDIT_POLICY_INFORMATION
                {
                    AuditSubCategoryGuid = subCategory,
                    AuditingInformation = POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE
                }
            };
            return AuditSetSystemPolicy(info, 1);
        }
        catch { return false; }
    }
}
