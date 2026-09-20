using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace ClipboardGuard.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// SensitiveDataType — §3.2 sensitive data categories (proposal)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Category of sensitive data detected within clipboard content.
/// Matches the sensitive data categories table in proposal §3.2 / Fig. 2.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum SensitiveDataType
{
    // ── PII ──────────────────────────────────────────────────────────────────

    /// <summary>Full legal name (first + last).</summary>
    FullName,

    /// <summary>National identification / social security number.</summary>
    NationalId,

    /// <summary>Passport number.</summary>
    PassportNumber,

    /// <summary>Driver's licence number.</summary>
    DriverLicence,

    /// <summary>Date of birth (various formats).</summary>
    DateOfBirth,

    /// <summary>Physical mailing address.</summary>
    Address,

    /// <summary>Email address.</summary>
    EmailAddress,

    /// <summary>Phone / mobile number.</summary>
    PhoneNumber,

    // ── Financial ────────────────────────────────────────────────────────────

    /// <summary>Payment card number (Visa, Mastercard, Amex, etc.).</summary>
    CreditCardNumber,

    /// <summary>Bank account number.</summary>
    BankAccountNumber,

    /// <summary>SWIFT / BIC bank identifier code.</summary>
    SwiftBic,

    /// <summary>IBAN — International Bank Account Number.</summary>
    Iban,

    /// <summary>Tax identification number / VAT number.</summary>
    TaxIdNumber,

    // ── Credentials ──────────────────────────────────────────────────────────

    /// <summary>Plain-text or weakly-encoded password.</summary>
    Password,

    /// <summary>API key or secret key string.</summary>
    ApiKey,

    /// <summary>OAuth / JWT / session bearer token.</summary>
    AuthToken,

    /// <summary>Private key material (RSA, EC, SSH private key blocks).</summary>
    PrivateKey,

    /// <summary>Connection string containing embedded credentials.</summary>
    ConnectionString,

    // ── Network ──────────────────────────────────────────────────────────────

    /// <summary>IPv4 or IPv6 address (internal and external).</summary>
    IpAddress,

    /// <summary>MAC / hardware address.</summary>
    MacAddress,

    /// <summary>Internal or sensitive URL / endpoint.</summary>
    Url,

    /// <summary>SSH known-hosts entry or SSH fingerprint.</summary>
    SshFingerprint,

    // ── Organisational Information ────────────────────────────────────────────

    /// <summary>Internal project name, code name, or product identifier.</summary>
    ProjectCodename,

    /// <summary>Business-confidential financial figure or forecast.</summary>
    ConfidentialFinancialData,

    /// <summary>Employee personal record (HR data).</summary>
    HrRecord,

    /// <summary>Proprietary source code snippet flagged by policy.</summary>
    SourceCode,

    /// <summary>Internal domain name or hostname.</summary>
    InternalDomainName
}

// ─────────────────────────────────────────────────────────────────────────────
// SensitiveMatch — individual detection hit inside a ClipboardContent
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Describes a single occurrence of sensitive data found within the clipboard text.
/// <para>
/// Per proposal §3.2 and README constraint: this record holds only the <em>position</em>
/// and <em>type</em> of the match — not the matched text itself — so that sensitive
/// values are never persisted beyond the detection step.
/// </para>
/// </summary>
public sealed class SensitiveMatch
{
    /// <summary>Category of sensitive data that was detected.</summary>
    [JsonProperty("dataType")]
    public SensitiveDataType DataType { get; init; }

    /// <summary>
    /// Zero-based character index within <see cref="ClipboardContent.RawText"/>
    /// where the match begins.
    /// </summary>
    [JsonProperty("startIndex")]
    public int StartIndex { get; init; }

    /// <summary>Number of characters the match spans in the source text.</summary>
    [JsonProperty("length")]
    public int Length { get; init; }

    /// <summary>Risk level assigned to this particular match.</summary>
    [JsonProperty("riskLevel")]
    public RiskLevel RiskLevel { get; init; }

    /// <inheritdoc />
    public override string ToString() =>
        $"{DataType} at [{StartIndex}..{StartIndex + Length - 1}] ({RiskLevel})";
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionResult — §3.2
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Aggregated output of the Sensitive Data Detection Engine (Task 3).
/// Contains zero or more <see cref="SensitiveMatch"/> records describing what
/// sensitive data was found and where, without retaining the raw sensitive text.
/// </summary>
public sealed class DetectionResult
{
    /// <summary>
    /// All sensitive matches found in the clipboard content, ordered by
    /// <see cref="SensitiveMatch.StartIndex"/> ascending.
    /// Empty when no sensitive data was detected.
    /// </summary>
    [JsonProperty("matches")]
    public IReadOnlyList<SensitiveMatch> Matches { get; init; } = [];

    /// <summary>
    /// Convenience property — <see langword="true"/> when at least one match was found.
    /// </summary>
    [JsonIgnore]
    public bool HasSensitiveData => Matches.Count > 0;

    /// <summary>
    /// The highest <see cref="RiskLevel"/> across all matches, or
    /// <see cref="RiskLevel.Low"/> when there are no matches.
    /// </summary>
    [JsonIgnore]
    public RiskLevel MaxRiskLevel =>
        Matches.Count > 0
            ? Matches.Max(m => m.RiskLevel)
            : RiskLevel.Low;

    /// <summary>Number of distinct sensitive data types detected.</summary>
    [JsonIgnore]
    public int DistinctTypeCount =>
        Matches.Select(m => m.DataType).Distinct().Count();

    /// <summary>
    /// Returns a static <see cref="DetectionResult"/> representing a clean (no-match) result.
    /// </summary>
    public static readonly DetectionResult Clean = new();

    /// <inheritdoc />
    public override string ToString() =>
        HasSensitiveData
            ? $"DetectionResult: {Matches.Count} match(es), max risk = {MaxRiskLevel}"
            : "DetectionResult: clean";
}
