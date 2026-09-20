using Newtonsoft.Json;

namespace ClipboardGuard.Core.Models;

/// <summary>
/// The complete, immutable record of a single clipboard copy/paste event,
/// written to the SQLite event log by <c>ClipboardGuard.Data.EventLogger</c> (Task 5).
/// <para>
/// Represents the full pipeline output: what was copied, from where, what was
/// detected, what decision was made, and when each stage occurred.
/// </para>
/// <para>
/// <strong>Privacy note:</strong> Per proposal §3.2, this record must NOT contain
/// the raw sensitive text. Only masked or redacted values may be stored.
/// The <see cref="MaskedText"/> field holds the post-masking clipboard content;
/// the <see cref="Detection"/> field stores only positional hit metadata.
/// </para>
/// </summary>
public sealed class ClipboardEvent
{
    // ─────────────────────────────────────────────────────────────────────────
    // Identity
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Unique identifier for this event. Generated at creation time.
    /// Used as the primary key in the SQLite <c>clipboard_events</c> table.
    /// </summary>
    [JsonProperty("id")]
    public Guid Id { get; init; } = Guid.NewGuid();

    // ─────────────────────────────────────────────────────────────────────────
    // Source & destination
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Information about the process that performed the copy.</summary>
    [JsonProperty("source")]
    public SourceInfo Source { get; init; } = new();

    /// <summary>
    /// Information about the process that performed the paste.
    /// May be <see langword="null"/> if the event is still pending a paste
    /// (e.g. the clipboard was updated but no paste has been detected yet).
    /// </summary>
    [JsonProperty("destination")]
    public DestinationInfo? Destination { get; init; }

    // ─────────────────────────────────────────────────────────────────────────
    // Detection & masking
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Result of the sensitive data detection pass.
    /// Contains positional match metadata — no raw sensitive text.
    /// </summary>
    [JsonProperty("detection")]
    public DetectionResult Detection { get; init; } = DetectionResult.Clean;

    /// <summary>
    /// The clipboard text after masking has been applied, ready to be
    /// written back to the Windows clipboard. For <see cref="PolicyDecision.Allow"/>
    /// events this equals the original text; for <see cref="PolicyDecision.Block"/>
    /// events this is an empty string or a generic placeholder.
    /// </summary>
    [JsonProperty("maskedText")]
    public string MaskedText { get; init; } = string.Empty;

    // ─────────────────────────────────────────────────────────────────────────
    // Policy
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The policy decision reached after evaluating source, detection, and
    /// destination contexts together.
    /// </summary>
    [JsonProperty("decision")]
    public PolicyDecision Decision { get; init; }

    /// <summary>
    /// If <see cref="Decision"/> is <see cref="PolicyDecision.Confirm"/>, records
    /// whether the user ultimately approved or rejected the paste.
    /// <see langword="null"/> until the user responds, or for non-Confirm decisions.
    /// </summary>
    [JsonProperty("userConfirmed")]
    public bool? UserConfirmed { get; init; }

    // ─────────────────────────────────────────────────────────────────────────
    // Timestamps
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>UTC time when the clipboard copy was captured (pipeline start).</summary>
    [JsonProperty("copyTimestampUtc")]
    public DateTime CopyTimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// UTC time when the policy decision was finalised (pipeline end).
    /// </summary>
    [JsonProperty("decisionTimestampUtc")]
    public DateTime DecisionTimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// UTC time when the paste was detected, if applicable.
    /// <see langword="null"/> for copy-only events where no paste was observed.
    /// </summary>
    [JsonProperty("pasteTimestampUtc")]
    public DateTime? PasteTimestampUtc { get; init; }

    // ─────────────────────────────────────────────────────────────────────────
    // Convenience
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Total pipeline processing time from copy capture to decision, in milliseconds.
    /// </summary>
    [JsonIgnore]
    public double ProcessingMs =>
        (DecisionTimestampUtc - CopyTimestampUtc).TotalMilliseconds;

    /// <inheritdoc />
    public override string ToString() =>
        $"[{Id:D}] {Source.ProcessName} → {Destination?.ProcessName ?? "?"} | " +
        $"{Decision} | {Detection.Matches.Count} match(es) | {ProcessingMs:F1} ms";
}
