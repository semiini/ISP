using ClipboardGuard.Core.Models;

namespace ClipboardGuard.UI;

/// <summary>
/// Task 7 — Windows Forms shell (proposal §4, UI Framework).
/// <para>
/// Owns the system-tray presence and every user-facing interruption:
/// balloon alerts for <see cref="PolicyDecision.Mask"/> / <see cref="PolicyDecision.Block"/>,
/// a modal confirmation for <see cref="PolicyDecision.Confirm"/>, and the settings screen.
/// The pipeline (Task 8) runs it as its <see cref="ApplicationContext"/>.
/// </para>
/// </summary>
public sealed class TrayApplication : ApplicationContext
{
    private readonly NotifyIcon _tray;

    /// <summary>Per-category protection toggles shown in the settings screen.</summary>
    public GuardSettings Settings { get; } = new();

    /// <summary>Raised when the user asks to view the event log from the tray menu.</summary>
    public event EventHandler? ViewLogRequested;

    public TrayApplication()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Settings…", null, (_, _) => ShowSettings());
        menu.Items.Add("View event log…", null, (_, _) => ViewLogRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => Exit());

        _tray = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "ClipboardGuard — monitoring clipboard",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _tray.DoubleClick += (_, _) => ShowSettings();
    }

    /// <summary>
    /// Shows a non-blocking tray balloon describing a Mask or Block decision.
    /// Only the data types are named — never the sensitive values (README §2).
    /// </summary>
    public void ShowAlert(PolicyDecision decision, DetectionResult detection, DestinationInfo destination)
    {
        string types = DescribeTypes(detection);
        (string title, string body, ToolTipIcon icon) = decision switch
        {
            PolicyDecision.Block => ("Paste blocked",
                $"{types} was blocked from {destination.ProcessName} ({destination.Category}).",
                ToolTipIcon.Error),
            PolicyDecision.Mask => ("Content masked",
                $"{types} was masked before pasting into {destination.ProcessName} ({destination.Category}).",
                ToolTipIcon.Warning),
            _ => ("ClipboardGuard", $"{decision}: {types} → {destination.ProcessName}.", ToolTipIcon.Info)
        };

        _tray.ShowBalloonTip(5000, title, body, icon);
    }

    /// <summary>
    /// Blocks until the user approves or denies a <see cref="PolicyDecision.Confirm"/> paste.
    /// </summary>
    /// <returns><see langword="true"/> when the user allows the paste.</returns>
    public bool Confirm(SourceInfo source, DetectionResult detection, DestinationInfo destination)
    {
        string message =
            $"{DescribeTypes(detection)} is about to be pasted.\n\n" +
            $"From:  {source.ProcessName}  ({source.Category}, {source.RiskLevel} risk)\n" +
            $"To:    {destination.ProcessName}  ({destination.Category}, {destination.RiskLevel} risk)\n\n" +
            "Allow this paste?";

        return MessageBox.Show(message, "ClipboardGuard — confirm paste",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2)
            == DialogResult.Yes;
    }

    /// <summary>Opens the settings screen (modal), persisting changes into <see cref="Settings"/>.</summary>
    public void ShowSettings()
    {
        using var form = new SettingsForm(Settings);
        form.ShowDialog();
    }

    /// <summary>Summarises a detection as data-type names only — no raw values.</summary>
    private static string DescribeTypes(DetectionResult detection)
    {
        if (!detection.HasSensitiveData) return "Clipboard content";

        var types = detection.Matches.Select(m => m.DataType.ToString()).Distinct().ToList();
        return types.Count <= 3
            ? string.Join(", ", types)
            : $"{string.Join(", ", types.Take(3))} +{types.Count - 3} more";
    }

    private void Exit()
    {
        _tray.Visible = false;
        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _tray.Dispose();
        base.Dispose(disposing);
    }
}
