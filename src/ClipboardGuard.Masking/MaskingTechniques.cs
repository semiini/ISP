using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Masking;

/// <summary>
/// Implements the six masking techniques defined in proposal §3.3 / Fig. 3:
/// Full, Partial, CharacterLevel, SuffixPreserving, TokenPreserving, PatternBased.
/// </summary>
public static class MaskingTechniques
{
    public const string RedactedPlaceholder = "***REDACTED***";

    /// <summary>
    /// 1. Full Masking: Replace the entire sensitive value with a fixed placeholder.
    /// Example from proposal §3.3: "password123" → "***REDACTED***"
    /// </summary>
    public static string ApplyFull(string value)
    {
        if (string.IsNullOrEmpty(value))
            return RedactedPlaceholder;

        return RedactedPlaceholder;
    }

    /// <summary>
    /// 2. Partial Masking: Reveal only the first and/or last few characters; mask the middle.
    /// Example from proposal §3.3: "john.doe@example.com" → "jo**@example.com"
    /// </summary>
    public static string ApplyPartial(string value, SensitiveDataType dataType = SensitiveDataType.FullName)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        // Email address partial masking: "john.doe@example.com" → "jo**@example.com"
        int atIndex = value.IndexOf('@');
        if (atIndex > 0)
        {
            string localPart = value[..atIndex];
            string domainPart = value[atIndex..];

            string maskedLocal = localPart.Length switch
            {
                1 => "*",
                2 => localPart[0] + "*",
                _ => localPart[..2] + "**"
            };

            return maskedLocal + domainPart;
        }

        // Date of Birth partial masking: e.g. "1990-05-15" → "1990-**-**"
        if (dataType == SensitiveDataType.DateOfBirth && value.Length >= 4)
        {
            // Reveal year only
            if (value.Length == 10 && (value[4] == '-' || value[4] == '/' || value[4] == '.'))
            {
                char sep = value[4];
                return $"{value[..4]}{sep}**{sep}**";
            }
        }

        // Full Name partial masking: "Alice Montgomery" → "A**** Montgomery"
        if (dataType == SensitiveDataType.FullName)
        {
            var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                return parts[0][0] + new string('*', Math.Max(1, parts[0].Length - 1)) + " " + parts[^1];
            }
        }

        // General partial masking: keep first 2, "**", keep last 2 if length > 4
        if (value.Length <= 4)
        {
            return value.Length <= 2 ? new string('*', value.Length) : value[0] + "*" + value[^1];
        }

        return value[..2] + "**" + (value.Length > 6 ? value[^2..] : "");
    }

    /// <summary>
    /// 3. Character-Level Masking: Replace every character in the value with an asterisk,
    /// preserving the exact value length.
    /// Example from proposal §3.3: "SecretKey99" → "***********"
    /// </summary>
    public static string ApplyCharacterLevel(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        return new string('*', value.Length);
    }

    /// <summary>
    /// 4. Suffix-Preserving Masking: Preserve the last 4 characters/digits and mask all preceding.
    /// Example from proposal §3.3: "4111111111111234" → "************1234"
    /// </summary>
    public static string ApplySuffixPreserving(string value, int preserveCount = 4)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        if (value.Length <= preserveCount)
            return value;

        int maskLength = value.Length - preserveCount;
        var sb = new StringBuilder(value.Length);

        for (int i = 0; i < maskLength; i++)
        {
            char c = value[i];
            // Preserve formatting spaces and hyphens
            sb.Append(char.IsWhiteSpace(c) || c == '-' ? c : '*');
        }

        sb.Append(value[maskLength..]);
        return sb.ToString();
    }

    /// <summary>
    /// 5. Token-Preserving Masking: Tokenise the value into a format-preserving or deterministic token.
    /// Example from proposal §3.3: "MyS3cr3tP@ss!" → "TKN-a3f9c12e"
    /// </summary>
    public static string ApplyTokenPreserving(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "TKN-00000000";

        // Deterministic SHA-256 short token
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        string hex = Convert.ToHexString(hash)[..8].ToLowerInvariant();
        return $"TKN-{hex}";
    }

    /// <summary>
    /// 6. Pattern-Based Masking: Replace the value with a string that matches the format/pattern
    /// of the original but contains fictitious/synthetic data.
    /// Example from proposal §3.3: real NIC → synthetic NIC with same pattern and length;
    /// IPv4 → replace last octet with 0; Project Codename → synthetic codename.
    /// </summary>
    public static string ApplyPatternBased(string value, SensitiveDataType dataType)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        switch (dataType)
        {
            case SensitiveDataType.IpAddress:
                // Replace last octet of IPv4 with 0
                int lastDot = value.LastIndexOf('.');
                if (lastDot > 0 && !value.Contains(':'))
                {
                    return value[..(lastDot + 1)] + "0";
                }
                break;

            case SensitiveDataType.NationalId:
                // Synthetic NIC (replace digits with '9', keep suffix letters like V/X)
                var nicSb = new StringBuilder(value.Length);
                foreach (char c in value)
                {
                    nicSb.Append(char.IsDigit(c) ? '9' : c);
                }
                return nicSb.ToString();

            case SensitiveDataType.ProjectCodename:
                return "Project-SYNTHETIC";

            case SensitiveDataType.InternalDomainName:
                return "internal.example.corp";

            case SensitiveDataType.ConnectionString:
                // Mask password/uid in connection string while preserving structural keys
                string maskedConn = Regex.Replace(value, @"(?i)(password|pwd)\s*=\s*[^;]+", "$1=***REDACTED***");
                maskedConn = Regex.Replace(maskedConn, @"(?i)(user\s*id|uid)\s*=\s*[^;]+", "$1=***USER***");
                return maskedConn;
        }

        // Generic pattern-based fallback: digits → 9, letters → X, preserve punctuation/spaces
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (char.IsDigit(c))
                sb.Append('9');
            else if (char.IsLetter(c))
                sb.Append(char.IsUpper(c) ? 'X' : 'x');
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Applies the specified <see cref="MaskingTechnique"/> to the input sensitive value.
    /// </summary>
    public static string Apply(string value, MaskingTechnique technique, SensitiveDataType dataType)
    {
        return technique switch
        {
            MaskingTechnique.Full => ApplyFull(value),
            MaskingTechnique.Partial => ApplyPartial(value, dataType),
            MaskingTechnique.CharacterLevel => ApplyCharacterLevel(value),
            MaskingTechnique.SuffixPreserving => ApplySuffixPreserving(value),
            MaskingTechnique.TokenPreserving => ApplyTokenPreserving(value),
            MaskingTechnique.PatternBased => ApplyPatternBased(value, dataType),
            _ => ApplyFull(value)
        };
    }
}
