using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace ClipboardGuard.Core.Models;

/// <summary>
/// The final access-control decision produced by the policy evaluation step
/// that follows Destination Analysis (Task 6). Drives both the clipboard
/// action taken by the Masking Engine and the notification shown in the UI.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum PolicyDecision
{
    /// <summary>
    /// No sensitive data detected, or source/destination risk combination
    /// is within acceptable thresholds. The original clipboard content is
    /// passed through unchanged.
    /// </summary>
    Allow,

    /// <summary>
    /// Sensitive data was detected. The clipboard content is replaced with
    /// a masked version before being made available to the destination app.
    /// The user is notified but not interrupted.
    /// </summary>
    Mask,

    /// <summary>
    /// Destination is high-risk (e.g. external browser, AI tool) and the
    /// detected data is critical. The paste is silently blocked — the clipboard
    /// is cleared and the user is notified via tray alert.
    /// </summary>
    Block,

    /// <summary>
    /// The source/destination/data combination requires explicit user approval
    /// before proceeding. A modal confirmation dialog is shown; the paste is
    /// held until the user responds.
    /// </summary>
    Confirm
}
