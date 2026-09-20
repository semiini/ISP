using System.Diagnostics;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Data;
using ClipboardGuard.Destination;
using ClipboardGuard.Detection;
using ClipboardGuard.Masking;
using ClipboardGuard.SourceId;
using ClipboardGuard.UI;

namespace ClipboardGuard.App;

/// <summary>
/// Task 8 — the §4.4 process flow, in order:
/// <code>
/// copy → source ID → detection → masking → clipboard update
///      → destination analysis → decision → log
/// </code>
/// <para>
/// The copy half runs on <c>WM_CLIPBOARDUPDATE</c>: the clipboard is masked immediately,
/// so sensitive content is already protected before any application can read it. The
/// original text is held in memory only (never written to disk or into the event log) so
/// that a later <see cref="PolicyDecision.Allow"/> can restore it.
/// </para>
/// <para>
/// The destination half runs when focus moves to another application. Each new destination
/// is evaluated independently, so copying once and pasting into a text editor and then into
/// an AI tool produces two decisions.
/// </para>
/// </summary>
internal sealed class ClipboardPipeline
{
    /// <summary>How long a copy stays eligible for paste analysis before the raw text is dropped.</summary>
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Window during which our own clipboard writes are ignored as re-entrant updates.</summary>
    private static readonly TimeSpan SelfWriteWindow = TimeSpan.FromSeconds(2);

    private readonly SourceIdentifier _sourceIdentifier;
    private readonly DetectionEngine _detection;
    private readonly MaskingEngine _masking;
    private readonly DestinationEngine _destination;
    private readonly EventLogger _logger;
    private readonly TrayApplication _tray;

    private PendingCopy? _pending;
    private DateTime _suppressUntilUtc = DateTime.MinValue;

    public ClipboardPipeline(
        SourceIdentifier sourceIdentifier,
        DetectionEngine detection,
        MaskingEngine masking,
        DestinationEngine destination,
        EventLogger logger,
        TrayApplication tray)
    {
        _sourceIdentifier = sourceIdentifier;
        _detection        = detection;
        _masking          = masking;
        _destination      = destination;
        _logger           = logger;
        _tray             = tray;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Copy: source ID → detection → masking → clipboard update
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Handles <c>WM_CLIPBOARDUPDATE</c>.</summary>
    public void OnClipboardUpdated()
    {
        // Ignore the update our own masking write just caused.
        if (DateTime.UtcNow < _suppressUntilUtc)
        {
            _suppressUntilUtc = DateTime.MinValue;
            return;
        }

        if (!_tray.Settings.ProtectionEnabled)
        {
            _pending = null;
            return;
        }

        string rawText = ReadClipboardText();
        if (string.IsNullOrWhiteSpace(rawText))
        {
            _pending = null;
            return;
        }

        // [1] Source identification (§3.1)
        var source = _sourceIdentifier.GetCurrentSource();

        var content = new ClipboardContent
        {
            RawText       = rawText,
            CapturedAtUtc = DateTime.UtcNow,
            Source        = source,
        };

        // [2] Sensitive data detection (§3.2), narrowed to the categories the user enabled
        var detection = ApplyCategoryFilter(_detection.Detect(content));

        // [3] Masking + [4] clipboard update (§3.3) — applied up-front so the protected
        //     value is on the clipboard before any destination can read it.
        string maskedText = string.Empty;
        if (detection.HasSensitiveData)
        {
            maskedText = _masking.Mask(content, detection);
            WriteClipboard(() => _masking.TrySetClipboardText(maskedText));
        }

        _pending = new PendingCopy
        {
            Source       = source,
            Detection    = detection,
            RawText      = rawText,
            MaskedText   = maskedText,
            CopiedAtUtc  = content.CapturedAtUtc,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Paste: destination analysis → decision → log
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Handles a foreground-window change — the paste trigger (README Task 8).</summary>
    public void OnForegroundChanged(int foregroundPid)
    {
        var pending = _pending;
        if (pending is null || !_tray.Settings.ProtectionEnabled) return;

        // Expired copies drop their raw text rather than lingering in memory.
        if (DateTime.UtcNow - pending.CopiedAtUtc > PendingLifetime)
        {
            _pending = null;
            return;
        }

        // Still inside the copying application, or the same destination we just judged.
        if (foregroundPid == pending.Source.Pid || foregroundPid == pending.LastEvaluatedPid) return;
        pending.LastEvaluatedPid = foregroundPid;

        // [5] Destination analysis + [6] decision (§3.4)
        var (destination, decision) = _destination.Analyse(pending.Source, pending.Detection);

        bool? userConfirmed = null;
        if (decision == PolicyDecision.Confirm)
        {
            userConfirmed = _tray.Confirm(pending.Source, pending.Detection, destination);
            decision = userConfirmed.Value ? PolicyDecision.Allow : PolicyDecision.Block;
        }

        Apply(decision, pending);

        if (_tray.Settings.ShowAlerts && decision is PolicyDecision.Mask or PolicyDecision.Block)
            _tray.ShowAlert(decision, pending.Detection, destination);

        // [7] Log (§3.3 clipboard management)
        Log(pending, destination, decision, userConfirmed);

        // Blocking clears the clipboard, so there is nothing left to paste anywhere else.
        if (decision == PolicyDecision.Block) _pending = null;
    }

    /// <summary>Puts the clipboard into the state the decision requires.</summary>
    private void Apply(PolicyDecision decision, PendingCopy pending)
    {
        switch (decision)
        {
            // Restore the original — it was masked pre-emptively at copy-time.
            case PolicyDecision.Allow when pending.Detection.HasSensitiveData:
                WriteClipboard(() => _masking.TrySetClipboardText(pending.RawText));
                break;

            case PolicyDecision.Block:
                WriteClipboard(ClearClipboard);
                break;

            // Mask: the clipboard already holds the masked text from the copy stage.
            // Allow with no detections: nothing was changed.
            default:
                break;
        }
    }

    private void Log(PendingCopy pending, DestinationInfo destination, PolicyDecision decision, bool? userConfirmed)
    {
        var now = DateTime.UtcNow;
        var evt = new ClipboardEvent
        {
            Source               = pending.Source,
            Destination          = destination,
            Detection            = pending.Detection,
            // Only ever the masked representation — raw text is never persisted (README §2).
            MaskedText           = pending.MaskedText,
            Decision             = decision,
            UserConfirmed        = userConfirmed,
            CopyTimestampUtc     = pending.CopiedAtUtc,
            DecisionTimestampUtc = now,
            PasteTimestampUtc    = now,
        };

        // Fire-and-forget: SQLite writes must not stall the paste.
        // ponytail: unawaited write, add a queue if logging ever needs back-pressure.
        _ = _logger.LogAsync(evt).ContinueWith(
            t => Debug.WriteLine($"ClipboardGuard: event logging failed — {t.Exception?.GetBaseException().Message}"),
            TaskContinuationOptions.OnlyOnFaulted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Drops matches whose category the user switched off in Settings.</summary>
    private DetectionResult ApplyCategoryFilter(DetectionResult detection)
    {
        var enabled = _tray.Settings.EnabledTypes;
        var kept = detection.Matches.Where(m => enabled.Contains(m.DataType)).ToList();

        return kept.Count == detection.Matches.Count
            ? detection
            : new DetectionResult { Matches = kept };
    }

    /// <summary>Runs a clipboard write, suppressing the update it triggers.</summary>
    private void WriteClipboard(Action write)
    {
        _suppressUntilUtc = DateTime.UtcNow.Add(SelfWriteWindow);
        try
        {
            write();
        }
        catch (Exception ex)
        {
            _suppressUntilUtc = DateTime.MinValue;
            Debug.WriteLine($"ClipboardGuard: clipboard write failed — {ex.Message}");
        }
    }

    private static void ClearClipboard() => Clipboard.Clear();

    private static string ReadClipboardText()
    {
        try
        {
            return Clipboard.ContainsText() ? Clipboard.GetText() : string.Empty;
        }
        catch (Exception ex)
        {
            // Another process may hold the clipboard open.
            Debug.WriteLine($"ClipboardGuard: clipboard read failed — {ex.Message}");
            return string.Empty;
        }
    }

    /// <summary>
    /// A copy awaiting destination analysis. <see cref="RawText"/> lives here, in memory,
    /// only until the copy expires or is superseded.
    /// </summary>
    private sealed class PendingCopy
    {
        public required SourceInfo Source { get; init; }
        public required DetectionResult Detection { get; init; }
        public required string RawText { get; init; }
        public required string MaskedText { get; init; }
        public required DateTime CopiedAtUtc { get; init; }

        /// <summary>Destination already judged for this copy — prevents duplicate prompts.</summary>
        public int LastEvaluatedPid { get; set; }
    }
}
