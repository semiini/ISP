using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Detection.Patterns;

/// <summary>
/// Pattern rules for Credentials per proposal §3.2.
/// </summary>
public static class CredentialPatterns
{
    public static IEnumerable<SensitivePattern> GetPatterns()
    {
        // 1. Password (Risk: Critical)
        yield return new SensitivePattern(
            SensitiveDataType.Password,
            RiskLevel.Critical,
            new Regex(@"(?:\b(?:password|passwd|pwd|passphrase)\s*[:=]\s*['""]?)([^'"";\s\r\n]{4,128})['""]?", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 2. ApiKey (Risk: Critical)
        // AWS, GitHub, Slack, or generic API/secret key labels
        yield return new SensitivePattern(
            SensitiveDataType.ApiKey,
            RiskLevel.Critical,
            new Regex(@"(?:\bAKIA[0-9A-Z]{16}\b)|(?:\bgh[pousr]_[A-Za-z0-9_]{36,255}\b)|(?:\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b)|(?:\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['""]?([A-Za-z0-9_\-]{16,64})['""]?)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 3. AuthToken (Risk: Critical)
        // JWT (header.payload.signature) or Bearer header
        yield return new SensitivePattern(
            SensitiveDataType.AuthToken,
            RiskLevel.Critical,
            new Regex(@"(?:\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)|(?:\b(?:Bearer|Token)\s+([A-Za-z0-9_\-\.]{20,})\b)", RegexOptions.Compiled),
            rangeExtractor: m => m.Groups.Count > 1 && m.Groups[1].Success
                ? (m.Groups[1].Index, m.Groups[1].Length)
                : (m.Index, m.Length)
        );

        // 4. PrivateKey (Risk: Critical)
        yield return new SensitivePattern(
            SensitiveDataType.PrivateKey,
            RiskLevel.Critical,
            new Regex(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", RegexOptions.Compiled)
        );

        // 5. ConnectionString (Risk: Critical)
        yield return new SensitivePattern(
            SensitiveDataType.ConnectionString,
            RiskLevel.Critical,
            new Regex(@"(?:\b(?:Server|Data\s*Source)=[^;\r\n]+;.*?(?:User\s*Id|Uid)=[^;\r\n]+;.*?(?:Password|Pwd)=[^;\r\n]+(?:\b|;))|(?:\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s:]+:[^\s@]+@[^\s\/]+[^\s;]*\b)", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        );
    }
}
