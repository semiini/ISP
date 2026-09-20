using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Destination.Native;

namespace ClipboardGuard.Destination;

/// <summary>
/// Main entry point for the Destination Analysis Engine (Task 6).
/// <para>
/// Implements the flow in proposal §3.4 / Fig. 4:
/// <list type="number">
///   <item>Detect the foreground application at paste-time via <c>user32.dll</c>.</item>
///   <item>Classify it with <see cref="DestinationClassifier"/> into Trusted / Local /
///         External / Ai / Unknown and return a populated <see cref="DestinationInfo"/>.</item>
///   <item>Combine source risk + detection risk + destination category into a
///         <see cref="PolicyDecision"/> (<see cref="Evaluate"/>).</item>
/// </list>
/// </para>
/// </summary>
public sealed class DestinationEngine
{
    private const int MaxWindowTitleLength = 512;

    private readonly IReadOnlyCollection<string>? _trustedMarkers;

    /// <param name="trustedMarkers">
    /// Deployment-specific internal markers (intranet domains, corporate app or
    /// publisher names). Defaults to <see cref="DestinationClassifier.DefaultTrustedMarkers"/>.
    /// </param>
    public DestinationEngine(IReadOnlyCollection<string>? trustedMarkers = null)
        => _trustedMarkers = trustedMarkers;

    // ─────────────────────────────────────────────────────────────────────────
    // Step 1–2 — detect and classify the paste target
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Identifies the current foreground window and returns a populated
    /// <see cref="DestinationInfo"/>. Never returns <see langword="null"/>; when the
    /// target cannot be inspected (protected process, no foreground window) a
    /// best-effort <see cref="DestinationCategory.Unknown"/> result is returned.
    /// </summary>
    public DestinationInfo GetCurrentDestination()
    {
        IntPtr hwnd = NativeMethods.GetForegroundWindow();
        if (hwnd == IntPtr.Zero)
            return BuildFallback("(unknown)", 0, "(no foreground window)");

        NativeMethods.GetWindowThreadProcessId(hwnd, out uint pid);
        string windowTitle = ReadWindowTitle(hwnd);

        string processName;
        string executablePath;
        try
        {
            using var process = Process.GetProcessById((int)pid);
            processName    = process.ProcessName;
            executablePath = GetMainModuleFilePath(process);
        }
        catch
        {
            // Protected / elevated processes deny access — classify on the title alone.
            return Build("(protected)", (int)pid, windowTitle, string.Empty, null);
        }

        return Build(processName, (int)pid, windowTitle, executablePath, GetPublisher(executablePath));
    }

    /// <summary>
    /// Builds a <see cref="DestinationInfo"/> for a known process ID — useful when the
    /// paste target was captured elsewhere in the pipeline, and for testing.
    /// </summary>
    public DestinationInfo GetDestinationForPid(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            string executablePath = GetMainModuleFilePath(process);
            return Build(process.ProcessName, pid, process.MainWindowTitle ?? string.Empty,
                         executablePath, GetPublisher(executablePath));
        }
        catch
        {
            return BuildFallback("(protected)", pid, string.Empty);
        }
    }

    /// <summary>
    /// Detects the paste target and evaluates the policy in one call — the form the
    /// pipeline (Task 8) uses at paste-time.
    /// </summary>
    public (DestinationInfo Destination, PolicyDecision Decision) Analyse(
        SourceInfo source, DetectionResult detection)
    {
        var destination = GetCurrentDestination();
        return (destination, Evaluate(source, detection, destination));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Step 3 — policy evaluation (§3.4, Fig. 4 decision matrix)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Combines source risk, detected-data risk and destination category into the
    /// final <see cref="PolicyDecision"/>.
    /// <para>
    /// Clean content is always allowed. Otherwise the detected-data risk is escalated
    /// one level when the copy came from a <see cref="SourceCategory.Credential"/>
    /// source (a password manager) heading anywhere other than a trusted destination,
    /// then resolved against this matrix:
    /// </para>
    /// <code>
    /// dest \ risk | Low     Medium   High     Critical
    /// ------------|----------------------------------
    /// Trusted     | Allow   Allow    Allow    Mask
    /// Local       | Allow   Allow    Mask     Confirm
    /// External    | Allow   Mask     Confirm  Block
    /// Unknown     | Allow   Mask     Confirm  Block
    /// Ai          | Mask    Confirm  Block    Block
    /// </code>
    /// </summary>
    public static PolicyDecision Evaluate(
        SourceInfo source, DetectionResult detection, DestinationInfo destination)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(detection);
        ArgumentNullException.ThrowIfNull(destination);

        // Nothing sensitive in the clipboard — the destination is irrelevant.
        if (!detection.HasSensitiveData) return PolicyDecision.Allow;

        var risk = detection.MaxRiskLevel;

        // Source-aware escalation: credential-manager content is one level worse
        // everywhere except a trusted internal destination.
        if (source.Category == SourceCategory.Credential &&
            destination.Category != DestinationCategory.Trusted)
            risk = Escalate(risk);

        return destination.Category switch
        {
            DestinationCategory.Trusted => risk == RiskLevel.Critical
                ? PolicyDecision.Mask
                : PolicyDecision.Allow,

            DestinationCategory.Local => risk switch
            {
                RiskLevel.Critical => PolicyDecision.Confirm,
                RiskLevel.High     => PolicyDecision.Mask,
                _                  => PolicyDecision.Allow
            },

            DestinationCategory.Ai => risk switch
            {
                RiskLevel.Low    => PolicyDecision.Mask,
                RiskLevel.Medium => PolicyDecision.Confirm,
                _                => PolicyDecision.Block
            },

            // External, Unknown (Unknown is treated as External per §3.4)
            _ => risk switch
            {
                RiskLevel.Critical => PolicyDecision.Block,
                RiskLevel.High     => PolicyDecision.Confirm,
                RiskLevel.Medium   => PolicyDecision.Mask,
                _                  => PolicyDecision.Allow
            }
        };
    }

    private static RiskLevel Escalate(RiskLevel risk) =>
        risk == RiskLevel.Critical ? risk : risk + 1;

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    private DestinationInfo Build(
        string processName, int pid, string windowTitle, string executablePath, string? publisher)
    {
        var category = DestinationClassifier.Classify(
            processName, publisher, executablePath, windowTitle, _trustedMarkers);

        return new DestinationInfo
        {
            ProcessName    = processName,
            Pid            = pid,
            WindowTitle    = windowTitle,
            ExecutablePath = executablePath,
            Publisher      = publisher,
            Category       = category,
            RiskLevel      = DestinationClassifier.CategoryRisk(category),
        };
    }

    private static DestinationInfo BuildFallback(string processName, int pid, string windowTitle) =>
        new()
        {
            ProcessName = processName,
            Pid         = pid,
            WindowTitle = windowTitle,
            Category    = DestinationCategory.Unknown,
            RiskLevel   = DestinationClassifier.CategoryRisk(DestinationCategory.Unknown),
        };

    private static string ReadWindowTitle(IntPtr hwnd)
    {
        int len = NativeMethods.GetWindowTextLength(hwnd);
        if (len <= 0) return string.Empty;

        var sb = new StringBuilder(Math.Min(len + 1, MaxWindowTitleLength));
        NativeMethods.GetWindowText(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

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

    // ponytail: duplicated from SourceIdentifier — module boundaries (README §2) keep
    // shared helpers out of Core, so ~20 lines are copied rather than extracted.
    private static string? GetPublisher(string executablePath)
    {
        if (string.IsNullOrEmpty(executablePath)) return null;

        try
        {
            var cert = X509CertificateLoader.LoadCertificateFromFile(executablePath);
            return ParseCommonName(cert.Subject);
        }
        catch
        {
            // Unsigned, missing, or unreadable — not an error.
            return null;
        }
    }

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
}
