using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Detection.Patterns;

/// <summary>
/// Pattern rules for Personally Identifiable Information (PII) per proposal §3.2.
/// </summary>
public static class PiiPatterns
{
    public static IEnumerable<SensitivePattern> GetPatterns()
    {
        // 1. EmailAddress (Risk: Medium)
        yield return new SensitivePattern(
            SensitiveDataType.EmailAddress,
            RiskLevel.Medium,
            new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        );

        // 2. PhoneNumber (Risk: Medium)
        // Supports international formats, US/CA formatted, and common regional formats
        yield return new SensitivePattern(
            SensitiveDataType.PhoneNumber,
            RiskLevel.Medium,
            new Regex(@"(?:\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b)|(?:\b(?:\+94|0)7[0-9]{8}\b)", RegexOptions.Compiled)
        );

        // 3. NationalId (Risk: High)
        // US SSN, Sri Lanka NIC (9 digits + V/X or 12 digits), UK National Insurance
        yield return new SensitivePattern(
            SensitiveDataType.NationalId,
            RiskLevel.High,
            new Regex(@"(?:\b\d{3}-\d{2}-\d{4}\b)|(?:\b(?:NIC|National ID|SSN|NIN)\s*[:=]?\s*([0-9]{9}[vVxX]|[0-9]{12})\b)|(?:\b[0-9]{9}[vVxX]\b)|(?:\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 4. PassportNumber (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.PassportNumber,
            RiskLevel.High,
            new Regex(@"(?:\b(?:Passport(?:\s*(?:No|Number|#))?\s*[:=]?\s*)([A-Z0-9]{6,9})\b)|(?:\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 5. DriverLicence (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.DriverLicence,
            RiskLevel.High,
            new Regex(@"(?:\b(?:Driver['’]?s?\s*Licen[sc]e(?:\s*(?:No|Number|#))?\s*[:=]?\s*)([A-Z0-9-]{5,15})\b)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 6. DateOfBirth (Risk: Medium)
        yield return new SensitivePattern(
            SensitiveDataType.DateOfBirth,
            RiskLevel.Medium,
            new Regex(@"(?:\b(?:DOB|Date\s*of\s*Birth|Birthdate)\s*[:=]?\s*)(\d{4}[-/.]\d{2}[-/.]\d{2}|\d{2}[-/.]\d{2}[-/.]\d{4})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 7. Address (Risk: Medium)
        yield return new SensitivePattern(
            SensitiveDataType.Address,
            RiskLevel.Medium,
            new Regex(@"(?:\b(?:Address|Location)\s*[:=]?\s*)?(\b\d{1,5}\s+[A-Za-z0-9\s.,]{3,35}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Terrace|Ter|Place|Pl|Square|Sq|Circle|Cir|Parkway|Pkwy)\b[^\n,]*,\s*[A-Za-z\s]+(?:,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 8. FullName (Risk: Medium)
        // Explicitly labeled names, e.g. "Full Name: Alice Smith" or "Customer Name: Bob Johnson"
        yield return new SensitivePattern(
            SensitiveDataType.FullName,
            RiskLevel.Medium,
            new Regex(@"(?:\b(?:Full\s*Name|Customer\s*Name|Patient\s*Name|Employee\s*Name|Name)\s*[:=]\s*)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b", RegexOptions.Compiled),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );
    }
}
