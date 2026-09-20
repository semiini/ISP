using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Detection.Patterns;

/// <summary>
/// Defines a single pattern rule used to detect sensitive data within text.
/// </summary>
public sealed class SensitivePattern
{
    public SensitiveDataType DataType { get; }
    public RiskLevel RiskLevel { get; }
    public Regex Regex { get; }
    public Func<string, bool>? CustomValidator { get; }
    public Func<Match, (int StartIndex, int Length)>? RangeExtractor { get; }

    public SensitivePattern(
        SensitiveDataType dataType,
        RiskLevel riskLevel,
        Regex regex,
        Func<string, bool>? customValidator = null,
        Func<Match, (int StartIndex, int Length)>? rangeExtractor = null)
    {
        DataType = dataType;
        RiskLevel = riskLevel;
        Regex = regex;
        CustomValidator = customValidator;
        RangeExtractor = rangeExtractor;
    }
}
