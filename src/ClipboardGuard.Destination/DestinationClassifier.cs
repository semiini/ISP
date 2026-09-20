using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Destination;

/// <summary>
/// Pure-logic classifier that maps a paste-target process name / publisher /
/// executable path / window title to a <see cref="DestinationCategory"/> and
/// <see cref="RiskLevel"/>, following the destination classification table in
/// proposal §3.4 / Fig. 4.
/// <para>
/// Contains no WinAPI calls, so it is unit-testable without a Windows desktop
/// session. All string comparisons are case-insensitive.
/// </para>
/// </summary>
public static class DestinationClassifier
{
    // ─────────────────────────────────────────────────────────────────────────
    // §3.4 Destination Classification Table
    // ─────────────────────────────────────────────────────────────────────────
    //
    // Category | Risk     | Typical applications
    // ---------|----------|--------------------------------------------------
    // Trusted  | Low      | Org-vetted internal tools, managed corporate apps,
    //          |          | browser windows on an internal/intranet domain
    // Local    | Medium   | Word processors, text editors, local DB clients —
    //          |          | content stays on the machine
    // External | High     | Browsers on public sites, email clients, chat,
    //          |          | FTP/SCP transfer tools
    // Ai       | Critical | ChatGPT, Claude, Copilot, Gemini, Perplexity, ...
    // Unknown  | High     | Unidentifiable — treated as External
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Markers that identify an organisation-internal destination. Matched
    /// (case-insensitively, as substrings) against process name, publisher,
    /// executable path and window title. Callers can pass their own deployment
    /// list to <see cref="Classify"/>.
    /// </summary>
    public static readonly string[] DefaultTrustedMarkers =
    [
        ".corp", ".local", ".internal", ".intranet", "intranet",
    ];

    // AI chat / code-completion tools — desktop clients (process name)
    private static readonly HashSet<string> AiProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chatgpt", "claude", "copilot", "githubcopilot", "gemini", "perplexity",
        "poe", "grok", "lmstudio", "ollama", "jan", "cursor",
    };

    // AI services reached through a browser — matched against the window title
    private static readonly string[] AiTitleMarkers =
    [
        "chatgpt", "openai", "claude.ai", "anthropic", "copilot", "gemini",
        "bard", "perplexity", "huggingchat", "deepseek", "mistral ai", "grok",
        "poe.com", "you.com",
    ];

    // Internet-facing applications
    private static readonly HashSet<string> ExternalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browsers
        "chrome", "msedge", "firefox", "iexplore", "opera", "brave", "vivaldi",
        "safari", "arc", "chromium", "tor",
        // Email
        "outlook", "thunderbird", "mailbird", "emclient",
        // Chat / conferencing (cloud-hosted)
        "slack", "teams", "msteams", "discord", "telegram", "whatsapp",
        "signal", "skype", "zoom", "webex",
        // File transfer
        "filezilla", "winscp", "cyberduck", "putty", "psftp", "ftp",
        // Cloud storage clients
        "dropbox", "onedrive", "googledrivefs", "megasync",
    };

    // Applications that keep the pasted content on the local machine
    private static readonly HashSet<string> LocalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Text editors / word processors
        "notepad", "wordpad", "notepad++", "notepadplusplus", "sublime_text",
        "vim", "nvim", "gvim", "emacs", "atom", "write",
        "winword", "excel", "powerpnt", "onenote", "msaccess", "mspub",
        "soffice", "libreoffice", "wps",
        // Code editors / IDEs
        "code", "devenv", "idea64", "idea", "pycharm64", "pycharm",
        "webstorm64", "webstorm", "rider64", "rider", "clion64", "clion",
        "goland64", "goland", "phpstorm64", "phpstorm", "eclipse", "netbeans",
        // Local database clients
        "ssms", "dbeaver", "tableplus", "mysqlworkbench", "sqlitebrowser",
        "azuredatastudio", "pgadmin4",
        // Shell / terminals (local execution)
        "cmd", "powershell", "pwsh", "windowsterminal", "wt", "conhost", "mintty",
        // Local notes and misc
        "obsidian", "keepass", "keepassxc", "calc", "mspaint", "explorer",
    };

    /// <summary>
    /// Classifies a paste destination per proposal §3.4.
    /// Precedence is Ai → Trusted → External → Local → Unknown: an AI service
    /// wins even when reached through an otherwise-trusted browser, and an
    /// intranet window wins over the browser's generic External classification.
    /// </summary>
    /// <param name="processName">Executable name, with or without extension (e.g. "msedge").</param>
    /// <param name="publisher">Authenticode publisher, or <see langword="null"/>.</param>
    /// <param name="executablePath">Full path to the .exe, or empty.</param>
    /// <param name="windowTitle">Foreground window title — carries the browser's site/tab.</param>
    /// <param name="trustedMarkers">
    /// Deployment-specific internal markers (domains, corp app names, publisher).
    /// Defaults to <see cref="DefaultTrustedMarkers"/>.
    /// </param>
    public static DestinationCategory Classify(
        string processName,
        string? publisher,
        string executablePath,
        string windowTitle,
        IReadOnlyCollection<string>? trustedMarkers = null)
    {
        string name  = Path.GetFileNameWithoutExtension(processName ?? string.Empty).Trim();
        string pub   = publisher ?? string.Empty;
        string path  = executablePath ?? string.Empty;
        string title = windowTitle ?? string.Empty;

        // 1. AI tools — highest risk, so checked first.
        if (AiProcessNames.Contains(name)) return DestinationCategory.Ai;
        if (ContainsAny(title, AiTitleMarkers)) return DestinationCategory.Ai;

        // 2. Organisation-internal destinations.
        var markers = trustedMarkers ?? DefaultTrustedMarkers;
        if (markers.Count > 0 &&
            (ContainsAny(name, markers) || ContainsAny(pub, markers) ||
             ContainsAny(path, markers) || ContainsAny(title, markers)))
            return DestinationCategory.Trusted;

        // 3. Internet-facing applications.
        if (ExternalProcessNames.Contains(name)) return DestinationCategory.External;

        // 4. Local-only applications.
        if (LocalProcessNames.Contains(name)) return DestinationCategory.Local;

        // 5. Unidentified — handled as External by CategoryRisk / policy.
        return DestinationCategory.Unknown;
    }

    /// <summary>
    /// Maps a <see cref="DestinationCategory"/> to its baseline
    /// <see cref="RiskLevel"/> per proposal §3.4. <see cref="DestinationCategory.Unknown"/>
    /// is treated conservatively as <see cref="DestinationCategory.External"/>.
    /// </summary>
    public static RiskLevel CategoryRisk(DestinationCategory category) => category switch
    {
        DestinationCategory.Trusted  => RiskLevel.Low,
        DestinationCategory.Local    => RiskLevel.Medium,
        DestinationCategory.External => RiskLevel.High,
        DestinationCategory.Ai       => RiskLevel.Critical,
        DestinationCategory.Unknown  => RiskLevel.High,
        _                            => RiskLevel.High
    };

    private static bool ContainsAny(string haystack, IEnumerable<string> needles)
    {
        if (string.IsNullOrEmpty(haystack)) return false;
        foreach (var needle in needles)
            if (!string.IsNullOrEmpty(needle) &&
                haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
