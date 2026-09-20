using Newtonsoft.Json;

namespace ClipboardGuard.Core.Models;

/// <summary>
/// Represents the raw clipboard payload captured at copy-time, together with
/// contextual metadata about when and from where the copy occurred.
/// This is the first object produced by the pipeline and is handed off to the
/// Sensitive Data Detection Engine (Task 3).
/// </summary>
public sealed class ClipboardContent
{
    /// <summary>
    /// The full text string read from the clipboard at copy-time.
    /// This is the only place in the pipeline where the unmasked raw text is
    /// held; downstream, only masked or redacted representations are used.
    /// </summary>
    [JsonProperty("rawText")]
    public string RawText { get; init; } = string.Empty;

    /// <summary>
    /// UTC timestamp when the clipboard content was captured.
    /// Stored as ISO-8601 string for reliable JSON round-tripping.
    /// </summary>
    [JsonProperty("capturedAtUtc")]
    public DateTime CapturedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Metadata about the source process that performed the copy operation.
    /// Populated by the Source Identification Module (Task 2).
    /// </summary>
    [JsonProperty("source")]
    public SourceInfo Source { get; init; } = new();

    /// <summary>Character length of <see cref="RawText"/> (convenience accessor).</summary>
    [JsonIgnore]
    public int Length => RawText.Length;

    /// <summary>Returns <see langword="true"/> when <see cref="RawText"/> is empty or whitespace.</summary>
    [JsonIgnore]
    public bool IsEmpty => string.IsNullOrWhiteSpace(RawText);

    /// <inheritdoc />
    public override string ToString() =>
        $"ClipboardContent [{Length} chars] from {Source.ProcessName} at {CapturedAtUtc:u}";
}
