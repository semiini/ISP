using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Detection.Patterns;

/// <summary>
/// Pattern rules for Organisational Information per proposal §3.2.
/// </summary>
public static class OrganisationalPatterns
{
    public static IEnumerable<SensitivePattern> GetPatterns()
    {
        // 1. ConfidentialFinancialData (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.ConfidentialFinancialData,
            RiskLevel.High,
            new Regex(@"(?:\b(?:Confidential\s*:\s*(?:Revenue|Budget|Forecast|EBITDA|Profit)[^\n\r]*)|(?:\b(?:Q[1-4]|FY\d{2,4})\s+(?:Revenue|Budget|Forecast|Profit)\s*[:=]?\s*[\$€£]?\s*[0-9.,]+\s*(?:million|billion|M|B|k)?)|(?:\b(?:Budget|Revenue|Operating\s*Income)\s*[:=]\s*[\$€£]\s*[0-9.,]+[A-Za-z0-9\s]*))", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        );

        // 2. HrRecord (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.HrRecord,
            RiskLevel.High,
            new Regex(@"(?:\b(?:Employee\s*(?:ID|Number|#)|Staff\s*ID|Emp\s*#)\s*[:=]?\s*([A-Z0-9-]{3,15})\b)|(?:\b(?:Salary|Base\s*Pay|Performance\s*Rating)\s*[:=]\s*([^\n\r,;]+)\b)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 3. SourceCode (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.SourceCode,
            RiskLevel.High,
            new Regex(@"(?:\b(?:public|private|protected|internal)\s+(?:class|interface|struct|enum|record)\s+[A-Za-z0-9_]+)|(?:\b(?:public|private|protected)\s+(?:void|string|int|bool|Task)\s+[A-Za-z0-9_]+\s*\()|(?:\bdef\s+[A-Za-z0-9_]+\s*\([^)]*\)\s*:)|(?:\bfunction\s+[A-Za-z0-9_]+\s*\([^)]*\)\s*\{)|(?:\bnamespace\s+[A-Za-z0-9_.]+\s*;)", RegexOptions.Compiled)
        );

        // 4. ProjectCodename (Risk: Medium)
        yield return new SensitivePattern(
            SensitiveDataType.ProjectCodename,
            RiskLevel.Medium,
            new Regex(@"(?:\b(?:Project\s+[A-Z][a-zA-Z0-9_-]{2,30})|(?:PROJECT-[A-Z0-9_-]{2,30})|(?:\bCodename\s*[:=]\s*([A-Za-z0-9_-]{3,30})\b))", RegexOptions.Compiled),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 5. InternalDomainName (Risk: Medium)
        yield return new SensitivePattern(
            SensitiveDataType.InternalDomainName,
            RiskLevel.Medium,
            new Regex(@"\b(?:[a-zA-Z0-9-]+\.(?:corp|internal|local|lan|priv|intranet))\b|\bcorp\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        );
    }
}
