using ClipboardGuard.Core.Models;
using Xunit;

namespace ClipboardGuard.Destination.Tests;

/// <summary>
/// Task 6 coverage — destination classification (§3.4 table) and the
/// source + detection + destination policy matrix (Fig. 4).
/// </summary>
public class DestinationClassifierTests
{
    [Theory]
    // AI desktop clients
    [InlineData("chatgpt", "", DestinationCategory.Ai)]
    [InlineData("Claude.exe", "", DestinationCategory.Ai)]
    [InlineData("cursor", "", DestinationCategory.Ai)]
    // AI through a browser — window title decides
    [InlineData("msedge", "ChatGPT - Personal - Microsoft Edge", DestinationCategory.Ai)]
    [InlineData("chrome", "Claude.ai - Google Chrome", DestinationCategory.Ai)]
    [InlineData("chrome", "GitHub Copilot - Google Chrome", DestinationCategory.Ai)]
    // Internal / intranet destinations
    [InlineData("chrome", "Jira - tickets.acme.corp", DestinationCategory.Trusted)]
    [InlineData("msedge", "HR Portal - intranet", DestinationCategory.Trusted)]
    // Internet-facing
    [InlineData("chrome", "Gmail - Inbox", DestinationCategory.External)]
    [InlineData("outlook", "Inbox - Outlook", DestinationCategory.External)]
    [InlineData("filezilla", "sftp://files.example.com", DestinationCategory.External)]
    [InlineData("slack", "acme - Slack", DestinationCategory.External)]
    // Local
    [InlineData("notepad", "Untitled - Notepad", DestinationCategory.Local)]
    [InlineData("winword", "report.docx - Word", DestinationCategory.Local)]
    [InlineData("ssms", "SQLQuery1.sql", DestinationCategory.Local)]
    // Unidentified
    [InlineData("some-random-app", "Window", DestinationCategory.Unknown)]
    [InlineData("", "", DestinationCategory.Unknown)]
    public void Classify_MapsProcessAndTitleToCategory(
        string processName, string windowTitle, DestinationCategory expected) =>
        Assert.Equal(expected, DestinationClassifier.Classify(processName, null, string.Empty, windowTitle));

    [Fact]
    public void Classify_AiWinsOverInternalDomain()
    {
        // An AI service proxied on an internal host is still an AI destination.
        var category = DestinationClassifier.Classify(
            "chrome", null, string.Empty, "Copilot - ai.acme.corp");
        Assert.Equal(DestinationCategory.Ai, category);
    }

    [Fact]
    public void Classify_HonoursDeploymentTrustedMarkers()
    {
        var category = DestinationClassifier.Classify(
            "AcmeCrm", "Acme Holdings Ltd", @"C:\Program Files\Acme\AcmeCrm.exe", "Acme CRM",
            trustedMarkers: ["acme holdings"]);
        Assert.Equal(DestinationCategory.Trusted, category);
    }

    [Fact]
    public void Classify_PublisherAndPathAreAlsoSearchedForMarkers()
    {
        Assert.Equal(DestinationCategory.Trusted, DestinationClassifier.Classify(
            "tool", null, @"C:\corp-tools\.internal\tool.exe", "Tool"));
    }

    [Theory]
    [InlineData(DestinationCategory.Trusted, RiskLevel.Low)]
    [InlineData(DestinationCategory.Local, RiskLevel.Medium)]
    [InlineData(DestinationCategory.External, RiskLevel.High)]
    [InlineData(DestinationCategory.Ai, RiskLevel.Critical)]
    [InlineData(DestinationCategory.Unknown, RiskLevel.High)]
    public void CategoryRisk_MatchesTable(DestinationCategory category, RiskLevel expected) =>
        Assert.Equal(expected, DestinationClassifier.CategoryRisk(category));
}

public class DestinationEnginePolicyTests
{
    private static SourceInfo Source(SourceCategory category = SourceCategory.Business) =>
        new() { ProcessName = "app", Category = category, RiskLevel = SourceRisk(category) };

    private static RiskLevel SourceRisk(SourceCategory category) => category switch
    {
        SourceCategory.Trusted     => RiskLevel.Low,
        SourceCategory.Development => RiskLevel.High,
        SourceCategory.Credential  => RiskLevel.Critical,
        _                          => RiskLevel.Medium
    };

    private static DetectionResult Detected(RiskLevel risk) =>
        new()
        {
            Matches =
            [
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.CreditCardNumber,
                    StartIndex = 0,
                    Length = 16,
                    RiskLevel = risk
                }
            ]
        };

    private static DestinationInfo Destination(DestinationCategory category) =>
        new()
        {
            ProcessName = "target",
            Category = category,
            RiskLevel = DestinationClassifier.CategoryRisk(category)
        };

    [Theory]
    [InlineData(DestinationCategory.Trusted)]
    [InlineData(DestinationCategory.Local)]
    [InlineData(DestinationCategory.External)]
    [InlineData(DestinationCategory.Ai)]
    [InlineData(DestinationCategory.Unknown)]
    public void Evaluate_CleanContentIsAlwaysAllowed(DestinationCategory category) =>
        Assert.Equal(PolicyDecision.Allow,
            DestinationEngine.Evaluate(Source(), DetectionResult.Clean, Destination(category)));

    [Theory]
    // Trusted
    [InlineData(DestinationCategory.Trusted, RiskLevel.Low, PolicyDecision.Allow)]
    [InlineData(DestinationCategory.Trusted, RiskLevel.High, PolicyDecision.Allow)]
    [InlineData(DestinationCategory.Trusted, RiskLevel.Critical, PolicyDecision.Mask)]
    // Local
    [InlineData(DestinationCategory.Local, RiskLevel.Medium, PolicyDecision.Allow)]
    [InlineData(DestinationCategory.Local, RiskLevel.High, PolicyDecision.Mask)]
    [InlineData(DestinationCategory.Local, RiskLevel.Critical, PolicyDecision.Confirm)]
    // External
    [InlineData(DestinationCategory.External, RiskLevel.Low, PolicyDecision.Allow)]
    [InlineData(DestinationCategory.External, RiskLevel.Medium, PolicyDecision.Mask)]
    [InlineData(DestinationCategory.External, RiskLevel.High, PolicyDecision.Confirm)]
    [InlineData(DestinationCategory.External, RiskLevel.Critical, PolicyDecision.Block)]
    // Unknown behaves as External
    [InlineData(DestinationCategory.Unknown, RiskLevel.Medium, PolicyDecision.Mask)]
    [InlineData(DestinationCategory.Unknown, RiskLevel.Critical, PolicyDecision.Block)]
    // AI
    [InlineData(DestinationCategory.Ai, RiskLevel.Low, PolicyDecision.Mask)]
    [InlineData(DestinationCategory.Ai, RiskLevel.Medium, PolicyDecision.Confirm)]
    [InlineData(DestinationCategory.Ai, RiskLevel.High, PolicyDecision.Block)]
    [InlineData(DestinationCategory.Ai, RiskLevel.Critical, PolicyDecision.Block)]
    public void Evaluate_FollowsDecisionMatrix(
        DestinationCategory destination, RiskLevel risk, PolicyDecision expected) =>
        Assert.Equal(expected,
            DestinationEngine.Evaluate(Source(), Detected(risk), Destination(destination)));

    [Fact]
    public void Evaluate_CredentialSourceEscalatesRiskOneLevel()
    {
        // Medium data to a local editor is normally allowed...
        Assert.Equal(PolicyDecision.Allow, DestinationEngine.Evaluate(
            Source(SourceCategory.Business), Detected(RiskLevel.Medium), Destination(DestinationCategory.Local)));

        // ...but the same paste out of a password manager is masked.
        Assert.Equal(PolicyDecision.Mask, DestinationEngine.Evaluate(
            Source(SourceCategory.Credential), Detected(RiskLevel.Medium), Destination(DestinationCategory.Local)));
    }

    [Fact]
    public void Evaluate_CredentialSourceDoesNotEscalateIntoTrustedDestination() =>
        Assert.Equal(PolicyDecision.Allow, DestinationEngine.Evaluate(
            Source(SourceCategory.Credential), Detected(RiskLevel.High), Destination(DestinationCategory.Trusted)));

    [Fact]
    public void Evaluate_CredentialSourceToAiEscalatesConfirmToBlock()
    {
        // Medium data into an AI tool is normally a Confirm...
        Assert.Equal(PolicyDecision.Confirm, DestinationEngine.Evaluate(
            Source(SourceCategory.Business), Detected(RiskLevel.Medium), Destination(DestinationCategory.Ai)));

        // ...but password-manager content is blocked outright.
        Assert.Equal(PolicyDecision.Block, DestinationEngine.Evaluate(
            Source(SourceCategory.Credential), Detected(RiskLevel.Medium), Destination(DestinationCategory.Ai)));
    }

    [Fact]
    public void Evaluate_UsesHighestRiskAcrossMatches()
    {
        var detection = new DetectionResult
        {
            Matches =
            [
                new SensitiveMatch { DataType = SensitiveDataType.EmailAddress, RiskLevel = RiskLevel.Low },
                new SensitiveMatch { DataType = SensitiveDataType.PrivateKey, RiskLevel = RiskLevel.Critical }
            ]
        };

        Assert.Equal(PolicyDecision.Block, DestinationEngine.Evaluate(
            Source(), detection, Destination(DestinationCategory.External)));
    }

    [Fact]
    public void Evaluate_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() =>
            DestinationEngine.Evaluate(null!, DetectionResult.Clean, Destination(DestinationCategory.Local)));
        Assert.Throws<ArgumentNullException>(() =>
            DestinationEngine.Evaluate(Source(), null!, Destination(DestinationCategory.Local)));
        Assert.Throws<ArgumentNullException>(() =>
            DestinationEngine.Evaluate(Source(), DetectionResult.Clean, null!));
    }

    [Fact]
    public void GetDestinationForPid_ReturnsFallbackForUnknownProcess()
    {
        var info = new DestinationEngine().GetDestinationForPid(-1);
        Assert.Equal(DestinationCategory.Unknown, info.Category);
        Assert.Equal(-1, info.Pid);
    }
}
