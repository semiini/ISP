using Xunit;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Masking.Tests;

/// <summary>
/// Unit tests for <see cref="MaskingEngine"/> and <see cref="MaskingTechniques"/>,
/// verifying all 6 techniques from proposal §3.3 table.
/// </summary>
public class MaskingEngineTests
{
    private readonly MaskingEngine _engine = new();

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Technique-Specific Worked Examples from Proposal §3.3
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void FullMasking_WorkedExample_ReplacesWithRedactedPlaceholder()
    {
        // Worked example from proposal §3.3: "password123" → "***REDACTED***"
        string input = "password123";
        string result = MaskingTechniques.ApplyFull(input);

        Assert.Equal("***REDACTED***", result);
    }

    [Fact]
    public void PartialMasking_WorkedExample_Email_RevealsPrefixAndDomain()
    {
        // Worked example from proposal §3.3: "john.doe@example.com" → "jo**@example.com"
        string input = "john.doe@example.com";
        string result = MaskingTechniques.ApplyPartial(input, SensitiveDataType.EmailAddress);

        Assert.Equal("jo**@example.com", result);
    }

    [Fact]
    public void CharacterLevelMasking_WorkedExample_ReplacesEveryCharPreservingLength()
    {
        // Worked example from proposal §3.3: "SecretKey99" → "***********"
        string input = "SecretKey99";
        string result = MaskingTechniques.ApplyCharacterLevel(input);

        Assert.Equal("***********", result);
        Assert.Equal(input.Length, result.Length);
    }

    [Fact]
    public void SuffixPreservingMasking_WorkedExample_CreditCard_PreservesLastFour()
    {
        // Worked example from proposal §3.3: "4111111111111234" → "************1234"
        string input = "4111111111111234";
        string result = MaskingTechniques.ApplySuffixPreserving(input, 4);

        Assert.Equal("************1234", result);
        Assert.EndsWith("1234", result);
        Assert.Equal(input.Length, result.Length);
    }

    [Fact]
    public void TokenPreservingMasking_WorkedExample_ReplacesWithToken()
    {
        // Worked example from proposal §3.3: "MyS3cr3tP@ss!" → "TKN-a3f9c12e"
        string input = "MyS3cr3tP@ss!";
        string result = MaskingTechniques.ApplyTokenPreserving(input);

        Assert.StartsWith("TKN-", result);
        Assert.NotEqual(input, result);

        // Deterministic token generation
        string result2 = MaskingTechniques.ApplyTokenPreserving(input);
        Assert.Equal(result, result2);
    }

    [Fact]
    public void PatternBasedMasking_WorkedExample_Nic_GeneratesSyntheticNic()
    {
        // Worked example from proposal §3.3: real NIC → synthetic NIC of same length/pattern
        string input = "951234567V";
        string result = MaskingTechniques.ApplyPatternBased(input, SensitiveDataType.NationalId);

        Assert.Equal("999999999V", result);
        Assert.Equal(input.Length, result.Length);
        Assert.EndsWith("V", result);
    }

    [Fact]
    public void PatternBasedMasking_IpAddress_ReplacesLastOctetWithZero()
    {
        string input = "192.168.1.145";
        string result = MaskingTechniques.ApplyPatternBased(input, SensitiveDataType.IpAddress);

        Assert.Equal("192.168.1.0", result);
    }

    [Fact]
    public void PatternBasedMasking_ConnectionString_RedactsCredentialsPreservesStructure()
    {
        string input = "Server=myServer;Database=myDb;User Id=myUser;Password=myPassword123;";
        string result = MaskingTechniques.ApplyPatternBased(input, SensitiveDataType.ConnectionString);

        Assert.Contains("Password=***REDACTED***", result);
        Assert.Contains("User Id=***USER***", result);
        Assert.DoesNotContain("myPassword123", result);
        Assert.Contains("Server=myServer", result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Engine End-to-End Masking Tests
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Mask_SingleMatch_AppliesDefaultRuleTechnique()
    {
        string rawText = "Your password is password123 for the account.";
        int startIndex = rawText.IndexOf("password123", StringComparison.Ordinal);

        var detection = new DetectionResult
        {
            Matches =
            [
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.Password,
                    StartIndex = startIndex,
                    Length = "password123".Length,
                    RiskLevel = RiskLevel.Critical
                }
            ]
        };

        string masked = _engine.Mask(rawText, detection);

        Assert.Equal("Your password is ***REDACTED*** for the account.", masked);
        Assert.DoesNotContain("password123", masked);
    }

    [Fact]
    public void Mask_MultipleMatches_ReplacesInReverseOrderPreservingOffsets()
    {
        string rawText = "User john.doe@example.com used card 4111111111111234 on 10.20.30.40.";

        int emailStart = rawText.IndexOf("john.doe@example.com", StringComparison.Ordinal);
        int cardStart = rawText.IndexOf("4111111111111234", StringComparison.Ordinal);
        int ipStart = rawText.IndexOf("10.20.30.40", StringComparison.Ordinal);

        var detection = new DetectionResult
        {
            Matches =
            [
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.EmailAddress,
                    StartIndex = emailStart,
                    Length = "john.doe@example.com".Length,
                    RiskLevel = RiskLevel.Medium
                },
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.CreditCardNumber,
                    StartIndex = cardStart,
                    Length = "4111111111111234".Length,
                    RiskLevel = RiskLevel.High
                },
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.IpAddress,
                    StartIndex = ipStart,
                    Length = "10.20.30.40".Length,
                    RiskLevel = RiskLevel.Medium
                }
            ]
        };

        string masked = _engine.Mask(rawText, detection);

        Assert.Contains("jo**@example.com", masked);
        Assert.Contains("************1234", masked);
        Assert.Contains("10.20.30.0", masked);
        Assert.DoesNotContain("john.doe@example.com", masked);
        Assert.DoesNotContain("4111111111111234", masked);
    }

    [Fact]
    public void Mask_CustomRuleOverrides_UsesSpecifiedTechnique()
    {
        string rawText = "Support email: support@service.com";
        int emailStart = rawText.IndexOf("support@service.com", StringComparison.Ordinal);

        var detection = new DetectionResult
        {
            Matches =
            [
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.EmailAddress,
                    StartIndex = emailStart,
                    Length = "support@service.com".Length,
                    RiskLevel = RiskLevel.Medium
                }
            ]
        };

        // Override default Partial with Full technique
        var customRules = new Dictionary<SensitiveDataType, MaskingRule>
        {
            [SensitiveDataType.EmailAddress] = new()
            {
                DataType = SensitiveDataType.EmailAddress,
                Technique = MaskingTechnique.Full
            }
        };

        string masked = _engine.Mask(rawText, detection, customRules);

        Assert.Equal("Support email: ***REDACTED***", masked);
    }

    [Fact]
    public void Mask_CleanDetectionResult_ReturnsOriginalText()
    {
        string clean = "Hello world, no sensitive data here.";
        string result = _engine.Mask(clean, DetectionResult.Clean);

        Assert.Equal(clean, result);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Mask_NullOrEmpty_ReturnsCleanString(string? text)
    {
        string result = _engine.Mask(text!, DetectionResult.Clean);
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Mask_ClipboardContent_Overload_ProducesCorrectResult()
    {
        var content = new ClipboardContent
        {
            RawText = "Secret key is SecretKey99."
        };

        int keyStart = content.RawText.IndexOf("SecretKey99", StringComparison.Ordinal);
        var detection = new DetectionResult
        {
            Matches =
            [
                new SensitiveMatch
                {
                    DataType = SensitiveDataType.ApiKey,
                    StartIndex = keyStart,
                    Length = "SecretKey99".Length,
                    RiskLevel = RiskLevel.Critical
                }
            ]
        };

        string result = _engine.Mask(content, detection);

        Assert.DoesNotContain("SecretKey99", result);
        Assert.StartsWith("Secret key is TKN-", result);
    }
}
