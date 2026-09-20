using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Detection.Validators;

namespace ClipboardGuard.Detection.Patterns;

/// <summary>
/// Pattern rules for Financial data per proposal §3.2.
/// </summary>
public static class FinancialPatterns
{
    public static IEnumerable<SensitivePattern> GetPatterns()
    {
        // 1. CreditCardNumber (Risk: High)
        // Standard Visa, MasterCard, Discover (16 digits), Amex (15 digits)
        yield return new SensitivePattern(
            SensitiveDataType.CreditCardNumber,
            RiskLevel.High,
            new Regex(@"(?:\b(?:4[0-9]{3}|5[1-5][0-9]{2}|6(?:011|5[0-9]{2}))[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b)|(?:\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b)", RegexOptions.Compiled),
            customValidator: LuhnValidator.IsValid
        );

        // 2. Iban (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.Iban,
            RiskLevel.High,
            new Regex(@"\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9A-Z]{4}){2,7}[ ]?[0-9A-Z]{1,4}\b", RegexOptions.Compiled),
            customValidator: IbanValidator.IsValid
        );

        // 3. SwiftBic (Risk: High)
        // ISO 9362: 4 letters (bank), 2 letters (country), 2 alphanumeric (location), optional 3 alphanumeric (branch)
        yield return new SensitivePattern(
            SensitiveDataType.SwiftBic,
            RiskLevel.High,
            new Regex(@"(?:\b(?:SWIFT|BIC|SWIFT/BIC)\s*[:=]?\s*)([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b|\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})\b", RegexOptions.Compiled),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 4. BankAccountNumber (Risk: High)
        yield return new SensitivePattern(
            SensitiveDataType.BankAccountNumber,
            RiskLevel.High,
            new Regex(@"(?:\b(?:Account\s*(?:Number|No|#)|Acc\s*#|Bank\s*Account)\s*[:=]?\s*)([0-9]{8,18})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 5. TaxIdNumber (Risk: High)
        // US EIN: 12-3456789 or labeled Tax ID / TIN / VAT
        yield return new SensitivePattern(
            SensitiveDataType.TaxIdNumber,
            RiskLevel.High,
            new Regex(@"(?:\b[0-9]{2}-[0-9]{7}\b)|(?:\b(?:Tax\s*ID|TIN|EIN|VAT(?:\s*(?:No|Number|#))?)\s*[:=]?\s*)([A-Z0-9-]{8,15})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );
    }
}
