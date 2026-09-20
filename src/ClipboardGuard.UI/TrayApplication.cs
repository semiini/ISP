using ClipboardGuard.Core.Models;

namespace ClipboardGuard.UI;

/// <summary>What the user chose when asked about a paste.</summary>
public enum PasteChoice
{
    /// <summary>Insert the real, unmasked value.</summary>
    Original,

    /// <summary>Insert the masked version.</summary>
    Redacted,

    /// <summary>Insert nothing; the clipboard keeps the masked copy.</summary>
    Cancel
}

/// <summary>
/// Task 7 — Windows Forms shell (proposal §4, UI Framework).
/// <para>
/// Owns the system-tray presence and every user-facing interruption: the three-way paste
/// prompt shown when sensitive content is about to be pasted, the copy-time notification,
/// and the settings screen. The pipeline (Task 8) runs it as its <see cref="ApplicationContext"/>.
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
    /// Asks the user how to paste sensitive content. Blocks until they choose.
    /// Only data types are named — never the values themselves (README §2).
    /// </summary>
    /// <param name="recommended">
    /// The §3.4 policy matrix result. It no longer acts on its own; it selects which button
    /// is highlighted, so the safe choice is the default exactly where the policy is strictest.
    /// </param>
    public PasteChoice AskPasteChoice(
        SourceInfo source,
        DetectionResult detection,
        DestinationInfo destination,
        PolicyDecision recommended)
    {
        var original = new TaskDialogCommandLinkButton("Paste original",
            "Insert the real value into this application.");
        var redacted = new TaskDialogCommandLinkButton("Paste redacted",
            "Insert the masked version instead.");
        var cancel = new TaskDialogCommandLinkButton("Cancel",
            "Paste nothing. The clipboard keeps the masked copy.");

        var page = new TaskDialogPage
        {
            Caption       = "ClipboardGuard",
            Heading       = $"Paste {DescribeTypes(detection)}?",
            Text          = $"From {source.ProcessName} ({source.Category}) " +
                            $"into {destination.ProcessName} ({destination.Category}, {destination.RiskLevel} risk).",
            Icon          = recommended == PolicyDecision.Block ? TaskDialogIcon.Warning : TaskDialogIcon.Information,
            Buttons       = [original, redacted, cancel],
            DefaultButton = recommended switch
            {
                PolicyDecision.Allow => original,
                PolicyDecision.Block => cancel,
                _                    => redacted,
            },
            AllowCancel = true,
        };

        // A hidden top-most owner keeps the prompt above the app being pasted into —
        // a background tray process cannot reliably steal the foreground on its own.
        using var owner = new Form
        {
            ShowInTaskbar   = false,
            FormBorderStyle = FormBorderStyle.None,
            StartPosition   = FormStartPosition.Manual,
            Location        = new Point(-32000, -32000),
            Size            = new Size(1, 1),
            TopMost         = true,
        };
        owner.Show();

        try
        {
            var result = TaskDialog.ShowDialog(owner, page);
            if (result == original) return PasteChoice.Original;
            if (result == redacted) return PasteChoice.Redacted;
            return PasteChoice.Cancel;
        }
        finally
        {
            owner.Close();
        }
    }

    /// <summary>
    /// Tray balloon shown when a copy was masked, so the user understands why their
    /// clipboard changed. Names data types only.
    /// </summary>
    public void ShowCopyAlert(DetectionResult detection) =>
        _tray.ShowBalloonTip(4000, "Sensitive data masked",
            $"{DescribeTypes(detection)} was masked on the clipboard. " +
            "You will be asked what to paste.", ToolTipIcon.Info);

    /// <summary>Opens the settings screen (modal), persisting changes into <see cref="Settings"/>.</summary>
    public void ShowSettings()
    {
        using var form = new SettingsForm(Settings);
        form.ShowDialog();
    }

    /// <summary>Summarises a detection as data-type names only — no raw values.</summary>
    private static string DescribeTypes(DetectionResult detection)
    {
        if (!detection.HasSensitiveData) return "clipboard content";

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
