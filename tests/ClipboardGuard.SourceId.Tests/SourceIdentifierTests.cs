using Xunit;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.SourceId.Tests;

/// <summary>
/// Unit tests for <see cref="SourceClassifier"/> — the pure-logic classifier
/// that maps process names / publishers / paths to <see cref="SourceCategory"/>
/// and <see cref="RiskLevel"/> per proposal §3.1.
///
/// These tests exercise the classifier in isolation (no WinAPI, no live processes)
/// so they run reliably in any CI environment.
/// </summary>
public class SourceClassifierTests
{
    // ─────────────────────────────────────────────────────────────────────────
    // Helper
    // ─────────────────────────────────────────────────────────────────────────

    private static SourceCategory Classify(
        string processName,
        string? publisher = null,
        string executablePath = "") =>
        SourceClassifier.Classify(processName, publisher, executablePath);

    // ─────────────────────────────────────────────────────────────────────────
    // Category: Trusted
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("explorer")]
    [InlineData("EXPLORER")]          // case-insensitive
    [InlineData("taskmgr")]
    [InlineData("regedit")]
    [InlineData("mmc")]
    [InlineData("cmd")]
    [InlineData("shellexperiencehost")]
    [InlineData("snippingtool")]
    public void Classify_TrustedProcessName_ReturnsTrusted(string processName)
    {
        var result = Classify(processName);
        Assert.Equal(SourceCategory.Trusted, result);
    }

    [Fact]
    public void Classify_System32Path_ReturnsTrusted()
    {
        var result = Classify(
            "someutil",
            publisher: null,
            executablePath: @"C:\Windows\System32\someutil.exe");

        Assert.Equal(SourceCategory.Trusted, result);
    }

    [Fact]
    public void Classify_SysWow64Path_ReturnsTrusted()
    {
        var result = Classify(
            "legacytool",
            publisher: null,
            executablePath: @"C:\Windows\SysWOW64\legacytool.exe");

        Assert.Equal(SourceCategory.Trusted, result);
    }

    [Fact]
    public void Classify_MicrosoftWindowsPublisher_ReturnsTrusted()
    {
        var result = Classify(
            "unknownsystemtool",
            publisher: "Microsoft Windows",
            executablePath: string.Empty);

        Assert.Equal(SourceCategory.Trusted, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Category: Business
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("winword")]
    [InlineData("EXCEL")]
    [InlineData("powerpnt")]
    [InlineData("outlook")]
    [InlineData("onenote")]
    [InlineData("chrome")]
    [InlineData("firefox")]
    [InlineData("msedge")]
    [InlineData("teams")]
    [InlineData("slack")]
    [InlineData("zoom")]
    [InlineData("acrord32")]
    [InlineData("thunderbird")]
    [InlineData("dropbox")]
    [InlineData("discord")]
    public void Classify_BusinessProcessName_ReturnsBusiness(string processName)
    {
        var result = Classify(processName);
        Assert.Equal(SourceCategory.Business, result);
    }

    [Fact]
    public void Classify_AdobePublisher_ReturnsBusiness()
    {
        var result = Classify(
            "adobereader",
            publisher: "Adobe Inc.",
            executablePath: string.Empty);

        Assert.Equal(SourceCategory.Business, result);
    }

    [Fact]
    public void Classify_ZoomPublisher_ReturnsBusiness()
    {
        var result = Classify(
            "zoom",
            publisher: "Zoom Video Communications, Inc.",
            executablePath: string.Empty);

        Assert.Equal(SourceCategory.Business, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Category: Development
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("devenv")]            // Visual Studio
    [InlineData("code")]              // VS Code
    [InlineData("cursor")]            // Cursor IDE
    [InlineData("idea64")]            // IntelliJ IDEA
    [InlineData("pycharm64")]
    [InlineData("rider64")]
    [InlineData("webstorm64")]
    [InlineData("windowsterminal")]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("postman")]
    [InlineData("gitkraken")]
    [InlineData("notepad++")]
    [InlineData("dbeaver")]
    [InlineData("wireshark")]
    public void Classify_DevelopmentProcessName_ReturnsDevelopment(string processName)
    {
        var result = Classify(processName);
        Assert.Equal(SourceCategory.Development, result);
    }

    [Fact]
    public void Classify_JetBrainsPublisher_ReturnsDevelopment()
    {
        var result = Classify(
            "idea64",
            publisher: "JetBrains s.r.o.",
            executablePath: string.Empty);

        Assert.Equal(SourceCategory.Development, result);
    }

    [Fact]
    public void Classify_NodeJsPath_ReturnsDevelopment()
    {
        var result = Classify(
            "node",
            publisher: null,
            executablePath: @"C:\Program Files\nodejs\node.exe");

        Assert.Equal(SourceCategory.Development, result);
    }

    [Fact]
    public void Classify_PythonPath_ReturnsDevelopment()
    {
        var result = Classify(
            "python",
            publisher: null,
            executablePath: @"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe");

        Assert.Equal(SourceCategory.Development, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Category: Credential
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("keepass")]
    [InlineData("keepassxc")]
    [InlineData("1password")]
    [InlineData("bitwarden")]
    [InlineData("lastpass")]
    [InlineData("dashlane")]
    [InlineData("roboform")]
    [InlineData("passwordsafe")]
    [InlineData("nordpass")]
    [InlineData("enpass")]
    public void Classify_CredentialProcessName_ReturnsCredential(string processName)
    {
        var result = Classify(processName);
        Assert.Equal(SourceCategory.Credential, result);
    }

    [Fact]
    public void Classify_AgileBitsPublisher_ReturnsCredential()
    {
        var result = Classify(
            "1password 8",
            publisher: "AgileBits Inc.",
            executablePath: string.Empty);

        Assert.Equal(SourceCategory.Credential, result);
    }

    [Fact]
    public void Classify_DominikReichlPublisher_ReturnsCredential()
    {
        var result = Classify(
            "keepass",
            publisher: "Dominik Reichl",
            executablePath: string.Empty);

        Assert.Equal(SourceCategory.Credential, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Category: Unknown (fallback)
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("somecustomapp")]
    [InlineData("mysteryproc")]
    [InlineData("xyz123")]
    public void Classify_UnknownProcessName_ReturnsUnknown(string processName)
    {
        var result = Classify(processName);
        Assert.Equal(SourceCategory.Unknown, result);
    }

    [Fact]
    public void Classify_EmptyProcessName_ReturnsUnknown()
    {
        var result = Classify(string.Empty);
        Assert.Equal(SourceCategory.Unknown, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Risk level mapping — §3.1 table
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(SourceCategory.Trusted,     RiskLevel.Low)]
    [InlineData(SourceCategory.Business,    RiskLevel.Medium)]
    [InlineData(SourceCategory.Development, RiskLevel.High)]
    [InlineData(SourceCategory.Credential,  RiskLevel.Critical)]
    [InlineData(SourceCategory.Unknown,     RiskLevel.Medium)]
    public void CategoryRisk_ReturnsCorrectRiskLevel(
        SourceCategory category, RiskLevel expectedRisk)
    {
        Assert.Equal(expectedRisk, SourceClassifier.CategoryRisk(category));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Credential takes priority over Development
    // (e.g. a credential manager that happens to be in a "dev tools" path)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Classify_CredentialManagerInDevPath_StillReturnsCredential()
    {
        var result = Classify(
            "keepass",
            publisher: null,
            executablePath: @"C:\Users\User\AppData\Local\Programs\KeePass\keepass.exe");

        Assert.Equal(SourceCategory.Credential, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Process-name extension stripping — "chrome.exe" → classified as Business
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Classify_ProcessNameWithExeExtension_StripsExtension()
    {
        // The classifier is passed process names without extensions by
        // SourceIdentifier (via Process.ProcessName), but Path.GetFileNameWithoutExtension
        // in the classifier handles it defensively.
        var result = Classify("chrome.exe");
        Assert.Equal(SourceCategory.Business, result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Case insensitivity
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("KEEPASS",     SourceCategory.Credential)]
    [InlineData("KeePassXC",   SourceCategory.Credential)]
    [InlineData("DEVENV",      SourceCategory.Development)]
    [InlineData("Code",        SourceCategory.Development)]
    [InlineData("CHROME",      SourceCategory.Business)]
    [InlineData("Explorer",    SourceCategory.Trusted)]
    public void Classify_IsCaseInsensitive(string processName, SourceCategory expected)
    {
        Assert.Equal(expected, Classify(processName));
    }
}
