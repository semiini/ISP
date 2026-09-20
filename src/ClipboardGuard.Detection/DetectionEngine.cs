using System.Text.RegularExpressions;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Detection.Patterns;

namespace ClipboardGuard.Detection;

/// <summary>
/// Sensitive Data Detection Engine (Task 3).
/// Scans clipboard text against pattern rules covering all 27 <see cref="SensitiveDataType"/>
/// categories from proposal §3.2 (PII, Financial, Credentials, Network, Organisational Information).
/// Returns a <see cref="DetectionResult"/> containing positional metadata only — never the raw sensitive values.
/// </summary>
public class DetectionEngine
{
    private readonly List<SensitivePattern> _patterns = [];

    /// <summary>
    /// Gets the list of registered detection patterns.
    /// </summary>
    public IReadOnlyList<SensitivePattern> Patterns => _patterns;

    /// <summary>
    /// Initialises the detection engine with standard pattern suites.
    /// </summary>
    public DetectionEngine()
    {
        RegisterDefaultPatterns();
    }

    /// <summary>
    /// Registers a custom pattern into the engine.
    /// </summary>
    public void RegisterPattern(SensitivePattern pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        _patterns.Add(pattern);
    }

    /// <summary>
    /// Registers default pattern suites covering all §3.2 sensitive categories.
    /// Order here defines initial evaluation priority.
    /// </summary>
    private void RegisterDefaultPatterns()
    {
        // 1. Credentials (Risk: Critical) - highest priority
        _patterns.AddRange(CredentialPatterns.GetPatterns());

        // 2. Financial (Risk: High) - validated by Luhn / Mod-97 checksums
        _patterns.AddRange(FinancialPatterns.GetPatterns());

        // 3. PII (Risk: High / Medium)
        _patterns.AddRange(PiiPatterns.GetPatterns());

        // 4. Organisational (Risk: High / Medium)
        _patterns.AddRange(OrganisationalPatterns.GetPatterns());

        // 5. Network (Risk: High / Medium / Low) - e.g. URLs evaluated last so specific secrets inside URLs are prioritized
        _patterns.AddRange(NetworkPatterns.GetPatterns());
    }

    /// <summary>
    /// Detects sensitive data within the provided <see cref="ClipboardContent"/>.
    /// </summary>
    public DetectionResult Detect(ClipboardContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Detect(content.RawText);
    }

    /// <summary>
    /// Scans the provided raw string and returns a populated <see cref="DetectionResult"/>.
    /// Guaranteed not to store raw sensitive text.
    /// </summary>
    public DetectionResult Detect(string? rawText)
    {
        if (string.IsNullOrEmpty(rawText))
        {
            return DetectionResult.Clean;
        }

        var candidateMatches = new List<SensitiveMatch>();

        foreach (var pattern in _patterns)
        {
            MatchCollection matches;
            try
            {
                matches = pattern.Regex.Matches(rawText);
            }
            catch (RegexMatchTimeoutException)
            {
                continue;
            }

            foreach (Match match in matches)
            {
                if (!match.Success)
                    continue;

                // Extract specific sub-range if defined (e.g. stripping field labels)
                int startIndex;
                int length;

                if (pattern.RangeExtractor != null)
                {
                    var range = pattern.RangeExtractor(match);
                    startIndex = range.StartIndex;
                    length = range.Length;
                }
                else
                {
                    startIndex = match.Index;
                    length = match.Length;
                }

                if (length <= 0 || startIndex < 0 || startIndex + length > rawText.Length)
                    continue;

                // Execute custom validator (Luhn, IBAN, IP octets, etc.) on matched span
                if (pattern.CustomValidator != null)
                {
                    string matchedSpan = rawText.Substring(startIndex, length);
                    if (!pattern.CustomValidator(matchedSpan))
                        continue;
                }

                candidateMatches.Add(new SensitiveMatch
                {
                    DataType = pattern.DataType,
                    StartIndex = startIndex,
                    Length = length,
                    RiskLevel = pattern.RiskLevel
                });
            }
        }

        if (candidateMatches.Count == 0)
        {
            return DetectionResult.Clean;
        }

        // Deduplicate overlapping matches:
        // Prioritize by highest RiskLevel, then longest match Length, then earlier StartIndex
        var sortedCandidates = candidateMatches
            .OrderByDescending(m => m.RiskLevel)
            .ThenByDescending(m => m.Length)
            .ThenBy(m => m.StartIndex)
            .ToList();

        var nonOverlapping = new List<SensitiveMatch>();

        foreach (var candidate in sortedCandidates)
        {
            int candStart = candidate.StartIndex;
            int candEnd = candidate.StartIndex + candidate.Length;

            bool overlaps = nonOverlapping.Any(existing =>
            {
                int exStart = existing.StartIndex;
                int exEnd = existing.StartIndex + existing.Length;
                return Math.Max(candStart, exStart) < Math.Min(candEnd, exEnd);
            });

            if (!overlaps)
            {
                nonOverlapping.Add(candidate);
            }
        }

        // Return sorted by StartIndex ascending
        var finalMatches = nonOverlapping.OrderBy(m => m.StartIndex).ToList();

        return new DetectionResult
        {
            Matches = finalMatches
        };
    }
}
