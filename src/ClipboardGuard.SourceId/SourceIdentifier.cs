using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ClipboardGuard.Core.Models;
using ClipboardGuard.SourceId.Native;

namespace ClipboardGuard.SourceId;

/// <summary>
/// Main entry point for the Source Identification Module (Task 2).
/// <para>
/// Implements the pipeline described in proposal §3.1 / Fig. 1:
/// <list type="number">
///   <item>Obtain the foreground window handle via <c>user32.dll GetForegroundWindow</c>.</item>
///   <item>Resolve the owning process via <c>GetWindowThreadProcessId</c>.</item>
///   <item>Read process name, executable path, and window title.</item>
///   <item>Extract the Authenticode publisher from the executable's digital signature.</item>
///   <item>Delegate to <see cref="SourceClassifier"/> to assign a category and risk level.</item>
///   <item>Return a fully populated <see cref="SourceInfo"/>.</item>
/// </list>
/// </para>
/// </summary>
public sealed class SourceIdentifier
{
    private const int MaxWindowTitleLength = 512;

    // ─────────────────────────────────────────────────────────────────────────
    // Primary API
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Identifies the currently active (foreground) window and returns a
    /// <see cref="SourceInfo"/> describing the process that owns it.
    /// Call this immediately when a <c>WM_CLIPBOARDUPDATE</c> message is received.
    /// </summary>
    /// <returns>
    /// A populated <see cref="SourceInfo"/>. Never returns <see langword="null"/>;
    /// if identification fails (e.g. the foreground window belongs to a protected
    /// process), a best-effort result with <see cref="SourceCategory.Unknown"/> is returned.
    /// </returns>
    public SourceInfo GetCurrentSource()
    {
        IntPtr hwnd = NativeMethods.GetForegroundWindow();
        if (hwnd == IntPtr.Zero)
            return BuildFallback("(unknown)", 0, "(no foreground window)", string.Empty);

        // Resolve owning process ID
        NativeMethods.GetWindowThreadProcessId(hwnd, out uint pid);

        // Read window title
        string windowTitle = ReadWindowTitle(hwnd);

        // Open the process to read its executable path and name
        string processName;
        string executablePath;

        try
        {
            using var process = Process.GetProcessById((int)pid);
            processName    = process.ProcessName;
            executablePath = GetMainModuleFilePath(process);
        }
        catch (Exception)
        {
            // Protected / system processes may deny access
            return BuildFallback("(protected)", (int)pid, windowTitle, string.Empty);
        }

        // Extract Authenticode publisher
        string? publisher = GetPublisher(executablePath);

        // Classify
        var category  = SourceClassifier.Classify(processName, publisher, executablePath);
        var riskLevel = SourceClassifier.CategoryRisk(category);

        return new SourceInfo
        {
            ProcessName    = processName,
            Pid            = (int)pid,
            WindowTitle    = windowTitle,
            ExecutablePath = executablePath,
            Publisher      = publisher,
            Category       = category,
            RiskLevel      = riskLevel,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Static convenience overload — identify a specific process by PID
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a <see cref="SourceInfo"/> for a known process ID (useful for
    /// testing or for cases where the PID is already known from another source).
    /// </summary>
    /// <param name="pid">The process ID to inspect.</param>
    public SourceInfo GetSourceForPid(int pid)
    {
        string processName;
        string executablePath;

        try
        {
            using var process = Process.GetProcessById(pid);
            processName    = process.ProcessName;
            executablePath = GetMainModuleFilePath(process);
        }
        catch
        {
            return BuildFallback("(protected)", pid, string.Empty, string.Empty);
        }

        string? publisher = GetPublisher(executablePath);
        var category      = SourceClassifier.Classify(processName, publisher, executablePath);
        var riskLevel     = SourceClassifier.CategoryRisk(category);

        return new SourceInfo
        {
            ProcessName    = processName,
            Pid            = pid,
            WindowTitle    = string.Empty,
            ExecutablePath = executablePath,
            Publisher      = publisher,
            Category       = category,
            RiskLevel      = riskLevel,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static string ReadWindowTitle(IntPtr hwnd)
    {
        int len = NativeMethods.GetWindowTextLength(hwnd);
        if (len <= 0) return string.Empty;

        var sb = new StringBuilder(Math.Min(len + 1, MaxWindowTitleLength));
        NativeMethods.GetWindowText(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    /// <summary>
    /// Safely retrieves the full path of a process's main module.
    /// Some system processes deny access; returns an empty string on failure.
    /// </summary>
    private static string GetMainModuleFilePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Reads the Authenticode Subject / publisher CN from the executable's
    /// embedded digital signature. Returns <see langword="null"/> if the file
    /// is unsigned, inaccessible, or the signature cannot be parsed.
    /// Uses <see cref="X509CertificateLoader"/> (the .NET 9+ replacement for
    /// the obsolete <c>X509Certificate.CreateFromSignedFile</c>).
    /// </summary>
    private static string? GetPublisher(string executablePath)
    {
        if (string.IsNullOrEmpty(executablePath)) return null;

        try
        {
            // X509CertificateLoader is the .NET 9+/10 API — no SYSLIB0057 warning.
            var cert = X509CertificateLoader.LoadCertificateFromFile(executablePath);
            // Subject DN looks like: "CN=Microsoft Corporation, O=Microsoft Corporation, ..."
            string subject = cert.Subject;
            return ParseCommonName(subject);
        }
        catch
        {
            // File unsigned, not found, or access denied — return null (not an error)
            return null;
        }
    }

    /// <summary>Extracts the CN= value from an X.500 distinguished name string.</summary>
    private static string? ParseCommonName(string distinguishedName)
    {
        const string prefix = "CN=";
        int idx = distinguishedName.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        int start = idx + prefix.Length;
        int comma = distinguishedName.IndexOf(',', start);
        return comma < 0
            ? distinguishedName[start..].Trim()
            : distinguishedName[start..comma].Trim();
    }

    private static SourceInfo BuildFallback(
        string processName, int pid, string windowTitle, string executablePath) =>
        new()
        {
            ProcessName    = processName,
            Pid            = pid,
            WindowTitle    = windowTitle,
            ExecutablePath = executablePath,
            Publisher      = null,
            Category       = SourceCategory.Unknown,
            RiskLevel      = RiskLevel.Medium,
        };
}
