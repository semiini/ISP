using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace ClipboardGuard.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// SourceCategory — §3.1 source classification table (proposal)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Classification category for the application that triggered a clipboard copy.
/// Matches the source classification table in proposal §3.1 / Fig. 1.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum SourceCategory
{
    /// <summary>
    /// System-level or organisation-vetted apps (e.g. Windows Explorer, corporate tools).
    /// Lowest sensitivity — minimal interception overhead.
    /// </summary>
    Trusted,

    /// <summary>
    /// General business productivity apps (e.g. Microsoft Office, web browsers, email clients).
    /// Moderate sensitivity — detection and policy enforcement apply.
    /// </summary>
    Business,

    /// <summary>
    /// IDEs, terminals, source-control tools, and other developer utilities.
    /// High sensitivity — source code, tokens, and credentials are common.
    /// </summary>
    Development,

    /// <summary>
    /// Dedicated credential or secret managers (e.g. KeePass, 1Password, Bitwarden).
    /// Highest sensitivity — all content treated as sensitive by default.
    /// </summary>
    Credential,

    /// <summary>
    /// Process could not be classified into any known category.
    /// Treated with the same caution as <see cref="Business"/>.
    /// </summary>
    Unknown
}

// ─────────────────────────────────────────────────────────────────────────────
// RiskLevel — shared across source, detection, and destination
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Ordinal risk level assigned to a source application, a detected sensitive data
/// match, or a destination application. Higher values indicate greater risk.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum RiskLevel
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

// ─────────────────────────────────────────────────────────────────────────────
// SourceInfo — §3.1
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Identifies the Windows process and application that initiated a clipboard copy
/// operation. Populated by the Source Identification Module (Task 2).
/// </summary>
public sealed class SourceInfo
{
    /// <summary>Process name (e.g. "WINWORD", "chrome", "code").</summary>
    [JsonProperty("processName")]
    public string ProcessName { get; init; } = string.Empty;

    /// <summary>Operating-system process ID.</summary>
    [JsonProperty("pid")]
    public int Pid { get; init; }

    /// <summary>Title of the foreground window at the time of the copy.</summary>
    [JsonProperty("windowTitle")]
    public string WindowTitle { get; init; } = string.Empty;

    /// <summary>Full path to the process executable on disk.</summary>
    [JsonProperty("executablePath")]
    public string ExecutablePath { get; init; } = string.Empty;

    /// <summary>
    /// Authenticode publisher name extracted from the executable's digital signature,
    /// or <see langword="null"/> if unsigned or unavailable.
    /// </summary>
    [JsonProperty("publisher")]
    public string? Publisher { get; init; }

    /// <summary>Classification of the source application per proposal §3.1.</summary>
    [JsonProperty("category")]
    public SourceCategory Category { get; init; } = SourceCategory.Unknown;

    /// <summary>
    /// Risk level derived from <see cref="Category"/> and any additional heuristics
    /// applied during source identification.
    /// </summary>
    [JsonProperty("riskLevel")]
    public RiskLevel RiskLevel { get; init; } = RiskLevel.Low;

    /// <inheritdoc />
    public override string ToString() =>
        $"{ProcessName} (PID {Pid}) [{Category}/{RiskLevel}] — \"{WindowTitle}\"";
}
