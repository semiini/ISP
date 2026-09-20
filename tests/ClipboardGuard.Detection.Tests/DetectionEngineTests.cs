using Xunit;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Detection.Tests.Data;
using ClipboardGuard.Detection.Validators;

namespace ClipboardGuard.Detection.Tests;

/// <summary>
/// Unit test suite for <see cref="DetectionEngine"/>, covering all 27 sensitive data categories,
/// true-positive detection, true-negative clean verification, and privacy constraints.
/// </summary>
public class DetectionEngineTests
{
    private readonly DetectionEngine _engine = new();

    public static IEnumerable<object[]> GetSensitiveSamples()
    {
        foreach (var sample in TestDataset.SensitiveSamples)
        {
            yield return [sample.DataType, sample.SampleText, sample.ExpectedRisk];
        }
    }

    public static IEnumerable<object[]> GetNonSensitiveSamples()
    {
        foreach (var sample in TestDataset.NonSensitiveSamples)
        {
            yield return [sample];
        }
    }

    [Theory]
    [MemberData(nameof(GetSensitiveSamples))]
    public void Detect_SensitiveSample_DetectsExpectedDataTypeAndRisk(
        SensitiveDataType expectedType,
        string sampleText,
        RiskLevel expectedRisk)
    {
        var result = _engine.Detect(sampleText);

        Assert.True(result.HasSensitiveData, $"Expected detection for sample: '{sampleText}'");
        Assert.NotEmpty(result.Matches);

        var match = result.Matches.FirstOrDefault(m => m.DataType == expectedType);
        Assert.NotNull(match);
        Assert.True(match.StartIndex >= 0);
        Assert.True(match.Length > 0);
        Assert.True(match.StartIndex + match.Length <= sampleText.Length);
        Assert.Equal(expectedRisk, match.RiskLevel);
    }

    [Theory]
    [MemberData(nameof(GetNonSensitiveSamples))]
    public void Detect_NonSensitiveSample_ReturnsClean(string cleanText)
    {
        var result = _engine.Detect(cleanText);

        Assert.False(result.HasSensitiveData, $"Expected clean text but matches found in: '{cleanText}'");
        Assert.Empty(result.Matches);
        Assert.Equal(RiskLevel.Low, result.MaxRiskLevel);
    }

    [Fact]
    public void Detect_PrivacyConstraint_NeverExposesRawSensitiveTextInMatches()
    {
        string sample = "Deploy with AKIAIOSFODNN7EXAMPLE and contact admin@corp.internal";
        var result = _engine.Detect(sample);

        Assert.True(result.HasSensitiveData);
        Assert.NotEmpty(result.Matches);

        // SensitiveMatch type must NOT contain raw string property or field
        var properties = typeof(SensitiveMatch).GetProperties();
        var propNames = properties.Select(p => p.Name).ToList();

        Assert.DoesNotContain("Text", propNames);
        Assert.DoesNotContain("Value", propNames);
        Assert.DoesNotContain("RawValue", propNames);
        Assert.DoesNotContain("RawText", propNames);
        Assert.DoesNotContain("MatchedText", propNames);

        // Verify that ToString() outputs positional info only
        foreach (var match in result.Matches)
        {
            string str = match.ToString();
            Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", str);
            Assert.DoesNotContain("admin@corp.internal", str);
        }
    }

    [Fact]
    public void Detect_MixedContent_DetectsMultipleNonOverlappingMatches()
    {
        string mixed = "Contact john@company.com with token ghp_1234567890abcdefghijklmnopqrstuvwxyz on host 10.0.0.1 immediately.";
        var result = _engine.Detect(mixed);

        Assert.True(result.HasSensitiveData);
        Assert.True(result.Matches.Count >= 3);

        // Verify sorted by StartIndex ascending
        for (int i = 0; i < result.Matches.Count - 1; i++)
        {
            var current = result.Matches[i];
            var next = result.Matches[i + 1];

            Assert.True(current.StartIndex < next.StartIndex);
            // No overlaps
            Assert.True(current.StartIndex + current.Length <= next.StartIndex);
        }

        // Verify MaxRiskLevel is Critical (due to GitHub PAT token)
        Assert.Equal(RiskLevel.Critical, result.MaxRiskLevel);
    }

    [Fact]
    public void Detect_ClipboardContent_PopulatesDetectionResultCorrectly()
    {
        var content = new ClipboardContent
        {
            RawText = "Confidential: Q3 Revenue $45.8 million exceeded expectations.",
            Source = new SourceInfo
            {
                ProcessName = "excel",
                Category = SourceCategory.Business,
                RiskLevel = RiskLevel.Medium
            }
        };

        var result = _engine.Detect(content);

        Assert.True(result.HasSensitiveData);
        var match = Assert.Single(result.Matches);
        Assert.Equal(SensitiveDataType.ConfidentialFinancialData, match.DataType);
        Assert.Equal(RiskLevel.High, match.RiskLevel);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Detect_NullOrEmpty_ReturnsClean(string? text)
    {
        var result = _engine.Detect(text);
        Assert.False(result.HasSensitiveData);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void LuhnValidator_ValidCards_PassValidation()
    {
        // Valid Luhn test card
        Assert.True(LuhnValidator.IsValid("4000 0012 3456 7899"));
        Assert.True(LuhnValidator.IsValid("4000001234567899"));
    }

    [Fact]
    public void LuhnValidator_InvalidCards_FailValidation()
    {
        // Invalid check digit
        Assert.False(LuhnValidator.IsValid("4000 0012 3456 7890"));
        // Too short
        Assert.False(LuhnValidator.IsValid("12345"));
        // Non-digits
        Assert.False(LuhnValidator.IsValid("4000-0012-3456-ABCD"));
    }

    [Fact]
    public void IbanValidator_ValidIban_PassValidation()
    {
        Assert.True(IbanValidator.IsValid("DE89 3704 0044 0532 0130 00"));
        Assert.True(IbanValidator.IsValid("DE89370400440532013000"));
    }

    [Fact]
    public void IbanValidator_InvalidIban_FailValidation()
    {
        // Wrong check digit
        Assert.False(IbanValidator.IsValid("DE89 3704 0044 0532 0130 01"));
        // Too short
        Assert.False(IbanValidator.IsValid("DE1234"));
        // Null or whitespace
        Assert.False(IbanValidator.IsValid(""));
    }
}
