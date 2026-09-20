using ClipboardGuard.Core.Models;

namespace ClipboardGuard.UI;

/// <summary>
/// User-adjustable protection settings, owned by <see cref="TrayApplication"/> and
/// read by the pipeline (Task 8) before running detection.
/// </summary>
public sealed class GuardSettings
{
    /// <summary>Sensitive data types currently protected. Defaults to all of them.</summary>
    public HashSet<SensitiveDataType> EnabledTypes { get; } =
        [.. Enum.GetValues<SensitiveDataType>()];

    /// <summary>When false, the pipeline passes clipboard content through untouched.</summary>
    public bool ProtectionEnabled { get; set; } = true;

    /// <summary>When false, Mask / Block decisions are applied silently (no tray balloon).</summary>
    public bool ShowAlerts { get; set; } = true;
}

/// <summary>
/// Basic settings screen (proposal §4): master switch, alert toggle, and a
/// per-category checklist of the §3.2 sensitive data types.
/// Built in code — no designer file.
/// </summary>
public sealed class SettingsForm : Form
{
    private readonly GuardSettings _settings;
    private readonly CheckedListBox _categories = new() { Dock = DockStyle.Fill, CheckOnClick = true };
    private readonly CheckBox _protection = new() { Text = "Protection enabled", AutoSize = true };
    private readonly CheckBox _alerts = new() { Text = "Show tray alerts", AutoSize = true };

    public SettingsForm(GuardSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));

        Text = "ClipboardGuard — Settings";
        Size = new Size(420, 520);
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;
        Icon = SystemIcons.Shield;

        _protection.Checked = settings.ProtectionEnabled;
        _alerts.Checked = settings.ShowAlerts;

        foreach (var type in Enum.GetValues<SensitiveDataType>())
            _categories.Items.Add(type, settings.EnabledTypes.Contains(type));

        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
        ok.Click += (_, _) => Save();

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(8),
        };
        buttons.Controls.AddRange([cancel, ok]);

        var toggles = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            Padding = new Padding(8),
        };
        toggles.Controls.AddRange([_protection, _alerts,
            new Label { Text = "Protected data types:", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }]);

        var list = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 0, 8, 0) };
        list.Controls.Add(_categories);

        Controls.AddRange([list, toggles, buttons]);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    private void Save()
    {
        _settings.ProtectionEnabled = _protection.Checked;
        _settings.ShowAlerts = _alerts.Checked;

        _settings.EnabledTypes.Clear();
        foreach (SensitiveDataType type in _categories.CheckedItems)
            _settings.EnabledTypes.Add(type);
    }
}
