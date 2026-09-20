using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace ClipboardGuard.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// DestinationCategory — §3.4 destination classification table (proposal)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Classification category for the application that is about to receive a
/// clipboard paste. Matches the destination classification table in proposal
/// §3.4 / Fig. 4.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum DestinationCategory
{
    /// <summary>
    /// Organisation-vetted internal tools and managed corporate applications.
    /// Pastes from trusted sources into trusted destinations may be allowed
    /// with minimal intervention.
    /// </summary>
    Trusted,

    /// <summary>
    /// Local productivity apps (word processors, local databases, text editors).
    /// Content stays on the machine; moderate risk depending on source sensitivity.
    /// </summary>
    Local,

    /// <summary>
    /// Internet-facing applications (web browsers on public sites, email clients,
    /// FTP/SCP tools). High risk — sensitive data could leave the organisation.
    /// </summary>
    External,

    /// <summary>
    /// AI chat / code completion tools (ChatGPT, GitHub Copilot, Gemini, etc.).
    /// Critical risk — sensitive data fed to AI models may be retained or leaked.
    /// </summary>
    Ai,

    /// <summary>
    /// Destination application could not be identified or classified.
    /// Treated conservatively — same policy as <see cref="External"/>.
    /// </summary>
    Unknown
}

// ─────────────────────────────────────────────────────────────────────────────
// DestinationInfo — §3.4
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Identifies the Windows process and application that is about to receive a
/// clipboard paste. Mirrors the structure of <see cref="SourceInfo"/> so the
/// two can be compared symmetrically in policy evaluation.
/// Populated by the Destination Analysis Engine (Task 6).
/// </summary>
public sealed class DestinationInfo
{
    /// <summary>Process name (e.g. "msedge", "notepad", "slack").</summary>
    [JsonProperty("processName")]
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>Operating-system process ID.</summary>
    [JsonProperty("pid")]
    public int Pid { get; init; }

    /// <summary>Title of the foreground window at the time of the paste.</summary>
    [JsonProperty("windowTitle")]
    public string WindowTitle { get; init; } = string.Empty;

    /// <summary>Full path to the destination process executable on disk.</summary>
    [JsonProperty("executablePath")]
    public string ExecutablePath { get; init; } = string.Empty;

    /// <summary>
    /// Authenticode publisher name, or <see langword="null"/> if unsigned / unavailable.
    /// </summary>
    [JsonProperty("publisher")]
    public string? Publisher { get; init; }

    /// <summary>Classification of the destination application per proposal §3.4.</summary>
    [JsonProperty("category")]
    public DestinationCategory Category { get; init; } = DestinationCategory.Unknown;

    /// <summary>
    /// Risk level derived from <see cref="Category"/> and destination-specific
    /// heuristics applied during destination analysis.
    /// </summary>
    [JsonProperty("riskLevel")]
    public RiskLevel RiskLevel { get; init; } = RiskLevel.Low;

    /// <inheritdoc />
    public override string ToString() =>
        $"{ProcessName} (PID {Pid}) [{Category}/{RiskLevel}] — \"{WindowTitle}\"";
}
