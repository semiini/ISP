using ClipboardGuard.Core.Models;

namespace ClipboardGuard.SourceId;

/// <summary>
/// Pure-logic classifier that maps a process name / executable path / publisher
/// to a <see cref="SourceCategory"/> and <see cref="RiskLevel"/>, following the
/// source classification table in proposal §3.1 / Fig. 1.
/// <para>
/// This class contains no WinAPI calls so it can be unit-tested without a real
/// Windows desktop session. All string comparisons are case-insensitive.
/// </para>
/// </summary>
public static class SourceClassifier
{
    // ─────────────────────────────────────────────────────────────────────────
    // §3.1 Source Classification Table
    // ─────────────────────────────────────────────────────────────────────────
    //
    // Category    | Risk  | Typical applications
    // ------------|-------|-----------------------------------------------------
    // Trusted     | Low   | Windows shell, File Explorer, Task Manager,
    //             |       | system utilities, corp-signed tools
    // Business    | Medium| Microsoft Office, Outlook, web browsers, Teams,
    //             |       | Slack, Zoom, email, PDF readers
    // Development | High  | VS, VS Code, JetBrains IDEs, terminals, git tools,
    //             |       | Postman, Docker Desktop
    // Credential  | Critical | KeePass, 1Password, Bitwarden, LastPass,
    //             |       | Dashlane, Windows Credential Manager
    // Unknown     | Medium| anything not matched above
    // ─────────────────────────────────────────────────────────────────────────

    // ── Trusted process names (executable stem, lower-case) ──────────────────
    private static readonly HashSet<string> TrustedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows shell & explorer
        "explorer", "shellexperiencehost", "searchhost", "searchapp",
        "startmenuexperiencehost", "lockapp",
        // System utilities
        "taskmgr", "mmc", "regedit", "cmd", "control", "rundll32",
        "svchost", "winlogon", "csrss", "dwm", "werfault",
        // Windows Settings / UWP
        "systemsettings", "settingssynchostpage",
        // Clipboard history (Windows built-in)
        "textinputhost",
        // Snipping / screen capture
        "snippingtool", "snagit32",
        // Corporate endpoint agents (common)
        "ccmexec",   // SCCM
        "igfxem",    // Intel graphics
    };

    // ── Trusted publisher substrings ──────────────────────────────────────────
    private static readonly string[] TrustedPublishers =
    [
        "microsoft windows",
        "microsoft corporation",
        "intel corporation",
        "dell inc",
        "hp inc",
        "lenovo",
    ];

    // ── Business process names ────────────────────────────────────────────────
    private static readonly HashSet<string> BusinessProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft Office suite
        "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess",
        "mspub", "visio", "msproject",
        // Office 365 / new names
        "word", "microsoftedge",
        // Web browsers
        "chrome", "msedge", "firefox", "iexplore", "opera", "brave", "vivaldi",
        "safari", "arc",
        // Communication & collaboration
        "teams", "msteams", "slack", "zoom", "webex", "skype", "telegram",
        "discord", "signal", "whatsapp",
        // Email clients
        "thunderbird", "mailbird",
        // PDF / document readers
        "acrord32", "acrobat", "foxitreader", "sumatrapdf",
        // Note-taking
        "notion", "obsidian", "evernote",
        // Cloud storage desktop
        "onedrive", "dropbox", "googledrivefs",
        // Remote desktop
        "mstsc", "vmconnect",
    };

    // ── Development process names ─────────────────────────────────────────────
    private static readonly HashSet<string> DevelopmentProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // IDEs
        "devenv",          // Visual Studio
        "code",            // VS Code
        "cursor",          // Cursor IDE
        "idea64", "idea",  // IntelliJ IDEA
        "pycharm64", "pycharm",
        "webstorm64", "webstorm",
        "rider64", "rider",
        "clion64", "clion",
        "goland64", "goland",
        "datagrip64", "datagrip",
        "phpstorm64", "phpstorm",
        "android studio",
        "eclipse",
        "netbeans",
        "xcode",
        // Terminals & shells
        "windowsterminal", "wt",
        "powershell", "pwsh",
        "bash", "zsh", "fish", "sh",
        "mintty",          // Git Bash / Cygwin
        "conhost",
        "hyper",           // Hyper terminal
        "alacritty",
        "wezterm-gui", "wezterm",
        // Version control GUIs
        "gitkraken", "sourcetree", "gitextensions", "fork",
        "github", "githubdesktop",
        // API / HTTP tools
        "postman", "insomnia", "httpie-desktop",
        // Database GUIs
        "dbeaver", "tableplus", "mysqlworkbench", "ssms", "azuredatastudio",
        // Containers / infra
        "docker desktop", "dockerdesktop", "rancher-desktop",
        "vagrant",
        // Text editors
        "notepad++", "notepadplusplus", "vim", "nvim", "gvim",
        "emacs", "atom", "sublime_text",
        // Build / task tools
        "msbuild", "gradle", "maven",
        // Packet / traffic analysis
        "wireshark", "fiddler", "charles",
    };

    // ── Credential-manager process names ─────────────────────────────────────
    private static readonly HashSet<string> CredentialProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "keepass", "keepassxc",
        "1password", "1password 7", "1password 8",
        "bitwarden",
        "lastpass",
        "dashlane",
        "roboform",
        "passwordsafe",
        "nordpass",
        "enpass",
        "buttercup",
        "passbolt",
        // Windows built-in credential UI
        "credentialuibroker",
        "vaultcmd",
    };

    // ── Credential publisher substrings ──────────────────────────────────────
    private static readonly string[] CredentialPublishers =
    [
        "agilebits",        // 1Password
        "bitwarden",
        "dominik reichl",   // KeePass
        "lastpass",
        "dashlane",
    ];

    // ── Development publisher substrings ─────────────────────────────────────
    private static readonly string[] DevelopmentPublishers =
    [
        "jetbrains",
        "github",
        "microsoft corporation",  // VS / VS Code
        "postman",
        "docker",
    ];

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Classifies an application into a <see cref="SourceCategory"/> using the
    /// process name (executable file stem), the publisher from the Authenticode
    /// signature, and the full executable path.
    /// </summary>
    /// <param name="processName">Executable name without extension (e.g. "chrome").</param>
    /// <param name="publisher">Publisher from digital signature, or <see langword="null"/>.</param>
    /// <param name="executablePath">Full path to the .exe, or empty string.</param>
    /// <returns>The best-matching <see cref="SourceCategory"/>.</returns>
    public static SourceCategory Classify(
        string processName,
        string? publisher,
        string executablePath)
    {
        // Normalise inputs
        string name = Path.GetFileNameWithoutExtension(processName).Trim();
        string pub  = publisher?.Trim() ?? string.Empty;
        string path = executablePath.Trim();

        // 1. Credential — highest specificity, check first
        if (IsCredential(name, pub, path)) return SourceCategory.Credential;

        // 2. Development
        if (IsDevelopment(name, pub, path)) return SourceCategory.Development;

        // 3. Business
        if (IsBusiness(name, pub, path)) return SourceCategory.Business;

        // 4. Trusted
        if (IsTrusted(name, pub, path)) return SourceCategory.Trusted;

        // 5. Fallback
        return SourceCategory.Unknown;
    }

    /// <summary>
    /// Maps a <see cref="SourceCategory"/> to its baseline <see cref="RiskLevel"/>
    /// per proposal §3.1.
    /// </summary>
    public static RiskLevel CategoryRisk(SourceCategory category) => category switch
    {
        SourceCategory.Trusted     => RiskLevel.Low,
        SourceCategory.Business    => RiskLevel.Medium,
        SourceCategory.Development => RiskLevel.High,
        SourceCategory.Credential  => RiskLevel.Critical,
        SourceCategory.Unknown     => RiskLevel.Medium,
        _                          => RiskLevel.Medium
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static bool IsCredential(string name, string pub, string path)
    {
        if (CredentialProcessNames.Contains(name)) return true;
        if (ContainsAny(pub, CredentialPublishers)) return true;
        if (ContainsAny(path, CredentialPublishers)) return true;
        return false;
    }

    private static bool IsDevelopment(string name, string pub, string path)
    {
        if (DevelopmentProcessNames.Contains(name)) return true;
        // Publisher match (but not Microsoft Windows — that's Trusted)
        if (!string.IsNullOrEmpty(pub))
        {
            var pubLow = pub.ToLowerInvariant();
            if (ContainsAny(pubLow, DevelopmentPublishers) &&
                !pubLow.Contains("microsoft windows"))
                return true;
        }
        // Path-based: common dev tool directories
        if (!string.IsNullOrEmpty(path))
        {
            var pathLow = path.ToLowerInvariant();
            if (pathLow.Contains("jetbrains") ||
                pathLow.Contains("\\git\\") ||
                pathLow.Contains("\\git for windows\\") ||
                pathLow.Contains("\\nodejs\\") ||
                pathLow.Contains("\\python") ||
                pathLow.Contains("\\ruby") ||
                pathLow.Contains("\\golang") ||
                pathLow.Contains("\\rustup"))
                return true;
        }
        return false;
    }

    private static bool IsBusiness(string name, string pub, string path)
    {
        if (BusinessProcessNames.Contains(name)) return true;
        // Publisher match for Office / Adobe
        if (!string.IsNullOrEmpty(pub))
        {
            var pubLow = pub.ToLowerInvariant();
            if (pubLow.Contains("adobe") ||
                pubLow.Contains("salesforce") ||
                pubLow.Contains("slack technologies") ||
                pubLow.Contains("zoom video"))
                return true;
        }
        return false;
    }

    private static bool IsTrusted(string name, string pub, string path)
    {
        if (TrustedProcessNames.Contains(name)) return true;
        if (!string.IsNullOrEmpty(pub) && ContainsAny(pub.ToLowerInvariant(), TrustedPublishers))
        {
            // Windows shell and system tools signed by Microsoft Windows are Trusted
            // (Microsoft Corporation covers Office too, so only accept it here
            //  if it's not already matched as Business above)
            if (pub.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        // Windows\System32 and Windows\SysWOW64 are always Trusted
        if (!string.IsNullOrEmpty(path))
        {
            var pathLow = path.ToLowerInvariant();
            if (pathLow.Contains(@"windows\system32\") ||
                pathLow.Contains(@"windows\syswow64\") ||
                pathLow.Contains(@"windows\systemapps\"))
                return true;
        }
        return false;
    }

    private static bool ContainsAny(string haystack, string[] needles)
    {
        var lower = haystack.ToLowerInvariant();
        foreach (var needle in needles)
            if (lower.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
