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
/// The copy half runs on <c>WM_CLIPBOARDUPDATE</c>: the clipboard is masked immediately, so
/// the protected value is the one sitting there before any application can read it. The
/// original is held in memory only — never on disk, never in the event log.
/// </para>
/// <para>
/// The destination half runs on a real paste (Ctrl+V / Shift+Insert, intercepted by
/// <see cref="PasteInterceptor"/>). Rather than deciding for the user, it runs destination
/// analysis and then asks: paste the original, paste the redacted version, or cancel. The
/// §3.4 matrix still runs — it chooses which answer is the default. This replaces the
/// foreground-change trigger named in README Task 8; the stage order is unchanged.
/// </para>
/// </summary>
internal sealed class ClipboardPipeline
{
    /// <summary>How long a copy stays eligible for paste analysis before the raw text is dropped.</summary>
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Window during which our own clipboard writes are ignored as re-entrant updates.</summary>
    private static readonly TimeSpan SelfWriteWindow = TimeSpan.FromSeconds(2);

    /// <summary>How long the real value stays on the clipboard after a "paste original".</summary>
    // ponytail: 300 ms reveal window, tune if slow apps read the clipboard late.
    private static readonly TimeSpan RevealWindow = TimeSpan.FromMilliseconds(300);

    private readonly SourceIdentifier _sourceIdentifier;
    private readonly DetectionEngine _detection;
    private readonly MaskingEngine _masking;
    private readonly DestinationEngine _destination;
    private readonly EventLogger _logger;
    private readonly TrayApplication _tray;

    private PendingCopy? _pending;
    private bool _prompting;
    private int _selfWrites;
    private DateTime _selfWriteExpiryUtc = DateTime.MinValue;

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

    /// <summary>
    /// Whether a paste should be intercepted right now. Read from inside the keyboard hook,
    /// so it must stay a pure in-memory check — no I/O, no allocation, no UI.
    /// </summary>
    public bool HasPendingSensitiveCopy =>
        !_prompting
        && _tray.Settings.ProtectionEnabled
        && _pending is { } pending
        && pending.Detection.HasSensitiveData
        && DateTime.UtcNow - pending.CopiedAtUtc <= PendingLifetime;

    // ─────────────────────────────────────────────────────────────────────────
    // Copy: source ID → detection → masking → clipboard update
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Handles <c>WM_CLIPBOARDUPDATE</c>.</summary>
    public void OnClipboardUpdated()
    {
        if (ConsumeSelfWrite()) return;

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

        // [3] Masking + [4] clipboard update (§3.3) — applied up-front, which is what makes
        //     Cancel free later: the safe value is already the one on the clipboard.
        string maskedText = string.Empty;
        if (detection.HasSensitiveData)
        {
            maskedText = _masking.Mask(content, detection);
            Write(() => _masking.TrySetClipboardText(maskedText));

            if (_tray.Settings.ShowAlerts) _tray.ShowCopyAlert(detection);
        }

        _pending = new PendingCopy
        {
            Source      = source,
            Detection   = detection,
            RawText     = rawText,
            MaskedText  = maskedText,
            CopiedAtUtc = content.CapturedAtUtc,
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Paste: destination analysis → user choice → log
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Handles an intercepted paste keystroke. The keystroke has already been swallowed, so
    /// every path except Cancel has to replay it.
    /// </summary>
    /// <param name="targetHwnd">The window that was about to receive the paste.</param>
    public async Task OnPasteAttemptAsync(IntPtr targetHwnd)
    {
        var pending = _pending;

        // Nothing sensitive in flight — let the paste through untouched.
        if (pending is null || !pending.Detection.HasSensitiveData || !_tray.Settings.ProtectionEnabled)
        {
            await PasteInterceptor.ReplayPasteAsync(targetHwnd);
            return;
        }

        // Expired copies drop their raw text rather than lingering in memory.
        if (DateTime.UtcNow - pending.CopiedAtUtc > PendingLifetime)
        {
            _pending = null;
            await PasteInterceptor.ReplayPasteAsync(targetHwnd);
            return;
        }

        // [5] Destination analysis + [6] policy (§3.4). Run before any UI is shown — the
        //     target application is still the foreground window at this point.
        var (destination, recommended) = _destination.Analyse(pending.Source, pending.Detection);

        PasteChoice choice;
        _prompting = true;   // a Ctrl+V while the prompt is open must not stack another prompt
        try
        {
            choice = _tray.AskPasteChoice(pending.Source, pending.Detection, destination, recommended);
        }
        finally
        {
            _prompting = false;
        }

        switch (choice)
        {
            case PasteChoice.Original:
                Write(() => _masking.TrySetClipboardText(pending.RawText));
                await PasteInterceptor.ReplayPasteAsync(targetHwnd);

                // Put the masked value back so the real one is not left for other apps.
                await Task.Delay(RevealWindow);
                Write(() => _masking.TrySetClipboardText(pending.MaskedText));
                break;

            case PasteChoice.Redacted:
                // The clipboard already holds the masked text from the copy stage.
                await PasteInterceptor.ReplayPasteAsync(targetHwnd);
                break;

            case PasteChoice.Cancel:
                // The keystroke was swallowed and the clipboard is untouched — nothing to undo.
                break;
        }

        // [7] Log (§3.3 clipboard management)
        Log(pending, destination, AsDecision(choice), choice != PasteChoice.Cancel);
    }

    /// <summary>Maps the answer onto the fixed §3.4 <see cref="PolicyDecision"/> values.</summary>
    private static PolicyDecision AsDecision(PasteChoice choice) => choice switch
    {
        PasteChoice.Original => PolicyDecision.Allow,
        PasteChoice.Redacted => PolicyDecision.Mask,
        _                    => PolicyDecision.Block,
    };

    private void Log(PendingCopy pending, DestinationInfo destination, PolicyDecision decision, bool userConfirmed)
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

    /// <summary>Runs a clipboard write and records that the update it raises is ours.</summary>
    private void Write(Action write)
    {
        _selfWrites++;
        _selfWriteExpiryUtc = DateTime.UtcNow.Add(SelfWriteWindow);
        try
        {
            write();
        }
        catch (Exception ex)
        {
            _selfWrites = Math.Max(0, _selfWrites - 1);
            Debug.WriteLine($"ClipboardGuard: clipboard write failed — {ex.Message}");
        }
    }

    /// <summary>
    /// True when this update was raised by one of our own writes. Counted rather than
    /// flagged, because "paste original" writes twice in quick succession.
    /// </summary>
    private bool ConsumeSelfWrite()
    {
        if (_selfWrites > 0 && DateTime.UtcNow < _selfWriteExpiryUtc)
        {
            _selfWrites--;
            return true;
        }

        _selfWrites = 0;   // stale — a write we expected an update for never produced one
        return false;
    }

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
    /// A copy awaiting a paste. <see cref="RawText"/> lives here, in memory, only until the
    /// copy expires or is superseded.
    /// </summary>
    private sealed class PendingCopy
    {
        public required SourceInfo Source { get; init; }
        public required DetectionResult Detection { get; init; }
        public required string RawText { get; init; }
        public required string MaskedText { get; init; }
        public required DateTime CopiedAtUtc { get; init; }
    }
}
