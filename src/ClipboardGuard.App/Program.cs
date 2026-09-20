using ClipboardGuard.Data;
using ClipboardGuard.Destination;
using ClipboardGuard.Detection;
using ClipboardGuard.Masking;
using ClipboardGuard.SourceId;
using ClipboardGuard.UI;

namespace ClipboardGuard.App;

/// <summary>
/// Task 8 — composition root. Builds every engine once, hooks the clipboard and the paste
/// keystroke, and runs the tray application message loop. All pipeline behaviour lives in
/// <see cref="ClipboardPipeline"/>.
/// </summary>
internal static class Program
{
    /// <summary>
    /// Machine-wide name for the single-instance guard. A second instance would install a
    /// second keyboard hook, so one Ctrl+V would raise two prompts and replay two pastes.
    /// </summary>
    private const string InstanceMutexName = @"Global\ClipboardGuard.SingleInstance";

    [STAThread]
    private static void Main()
    {
        using var instanceLock = new Mutex(initiallyOwned: true, InstanceMutexName, out bool isFirstInstance);
        if (!isFirstInstance)
        {
            MessageBox.Show(
                "ClipboardGuard is already running — look for the shield icon in the system tray.",
                "ClipboardGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        ApplicationConfiguration.Initialize();

        using var tray   = new TrayApplication();
        using var logger = new EventLogger();
        logger.EnsureInitializedAsync().GetAwaiter().GetResult();

        var pipeline = new ClipboardPipeline(
            new SourceIdentifier(),
            new DetectionEngine(),
            new MaskingEngine(),
            new DestinationEngine(),
            logger,
            tray);

        using var monitor = new ClipboardMonitor();
        monitor.ClipboardUpdated += (_, _) => pipeline.OnClipboardUpdated();

        using var interceptor = new PasteInterceptor(
            () => pipeline.HasPendingSensitiveCopy,
            pipeline.OnPasteAttemptAsync);

        tray.ViewLogRequested += async (_, _) => await ShowRecentEventsAsync(logger);

        Application.Run(tray);
    }

    /// <summary>
    /// Shows the most recent decisions from the SQLite log. Data types and decisions only —
    /// the log never holds raw sensitive values.
    /// </summary>
    private static async Task ShowRecentEventsAsync(EventLogger logger)
    {
        try
        {
            var events = await logger.QueryAsync(limit: 20);
            string body = events.Count == 0
                ? "No clipboard events recorded yet."
                : string.Join(Environment.NewLine, events.Select(e =>
                    $"{e.DecisionTimestampUtc.ToLocalTime():g}  {e.Decision,-7}  " +
                    $"{e.Source.ProcessName} → {e.Destination?.ProcessName ?? "(none)"}  " +
                    $"[{e.Detection.Matches.Count} match(es), max {e.Detection.MaxRiskLevel}]"));

            MessageBox.Show(body, "ClipboardGuard — recent events",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not read the event log:{Environment.NewLine}{ex.Message}",
                "ClipboardGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
