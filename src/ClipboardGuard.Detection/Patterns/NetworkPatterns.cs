using System.Net;
using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Detection.Patterns;

/// <summary>
/// Pattern rules for Network data per proposal §3.2.
/// </summary>
public static class NetworkPatterns
{
    public static IEnumerable<SensitivePattern> GetPatterns()
    {
        // 1. SshFingerprint (Risk: High)
        // Check SSH fingerprints before IP or URL to avoid sub-match collisions
        yield return new SensitivePattern(
            SensitiveDataType.SshFingerprint,
            RiskLevel.High,
            new Regex(@"(?:\bSHA256:[A-Za-z0-9+/=]{40,64}(?=[^A-Za-z0-9+/=]|$))|(?:\b(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}\b)", RegexOptions.Compiled)
        );

        // 2. MacAddress (Risk: Medium)
        yield return new SensitivePattern(
            SensitiveDataType.MacAddress,
            RiskLevel.Medium,
            new Regex(@"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", RegexOptions.Compiled)
        );

        // 3. IpAddress (Risk: Medium)
        // IPv4 (validated) and IPv6
        yield return new SensitivePattern(
            SensitiveDataType.IpAddress,
            RiskLevel.Medium,
            new Regex(@"(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|(?:\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b)|(?:\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b)", RegexOptions.Compiled),
            customValidator: text =>
            {
                if (IPAddress.TryParse(text, out var ip))
                {
                    // Check IPv4 octets strictly
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var parts = text.Split('.');
                        return parts.Length == 4 && parts.All(p => int.TryParse(p, out var v) && v is >= 0 and <= 255);
                    }
                    return true; // IPv6
                }
                return false;
            }
        );

        // 4. Url (Risk: Low)
        yield return new SensitivePattern(
            SensitiveDataType.Url,
            RiskLevel.Low,
            new Regex(@"\bhttps?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+", RegexOptions.Compiled | RegexOptions.IgnoreCase)
        );
    }
}
