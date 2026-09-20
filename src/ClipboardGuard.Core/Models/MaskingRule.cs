using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace ClipboardGuard.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// MaskingTechnique — §3.3 masking approaches table (proposal)
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// The six masking techniques defined in proposal §3.3 / Fig. 3.
/// The Masking Engine (Task 4) must implement each technique exactly as
/// described in the worked examples in the proposal's masking approaches table.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum MaskingTechnique
{
    /// <summary>
    /// Replace the entire sensitive value with asterisks or a fixed placeholder.
    /// Example: "password123" → "***REDACTED***"
    /// </summary>
    Full,

    /// <summary>
    /// Reveal only the first and/or last few characters; mask the middle.
    /// Example: "john.doe@example.com" → "jo**@example.com"
    /// </summary>
    Partial,

    /// <summary>
    /// Replace every character in the value with a masking character (e.g. '*').
    /// Preserves value length. Example: "SecretKey99" → "***********"
    /// </summary>
    CharacterLevel,

    /// <summary>
    /// Preserve a defined suffix (e.g. last 4 digits) and mask the rest.
    /// Example: "4111111111111234" → "************1234"
    /// </summary>
    SuffixPreserving,

    /// <summary>
    /// Tokenise the sensitive value with a reversible or irreversible token.
    /// Preserves format (length, character class) while destroying the real value.
    /// Example: "MyS3cr3tP@ss!" → "TKN-a3f9c12e"
    /// </summary>
    TokenPreserving,

    /// <summary>
    /// Replace the value with a string that matches the format/pattern of the
    /// original but contains fictitious data.
    /// Example: real NIC → synthetic NIC of same length and check-digit pattern.
    /// </summary>
    PatternBased
}

// ─────────────────────────────────────────────────────────────────────────────
// MaskingRule — §3.3
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Associates a <see cref="SensitiveDataType"/> with the <see cref="MaskingTechnique"/>
/// that should be applied when that data type is detected.
/// <para>
/// The Masking Engine (Task 4) resolves a <see cref="MaskingRule"/> for every
/// <see cref="SensitiveMatch"/> found in a <see cref="DetectionResult"/> and
/// then applies the designated technique.
/// </para>
/// </summary>
public sealed class MaskingRule
{
    /// <summary>The category of sensitive data this rule applies to.</summary>
    [JsonProperty("dataType")]
    public SensitiveDataType DataType { get; init; }

    /// <summary>The masking technique to apply for this data type.</summary>
    [JsonProperty("technique")]
    public MaskingTechnique Technique { get; init; }

    /// <summary>
    /// Optional human-readable description (e.g. "Mask all but last 4 digits").
    /// </summary>
    [JsonProperty("description")]
    public string? Description { get; init; }

    // ─────────────────────────────────────────────────────────────────────────
    // Default rule set — Task 4 may override per policy configuration.
    // Technique assignments are derived from the proposal §3.3 table.
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Default mapping of every <see cref="SensitiveDataType"/> to its
    /// recommended <see cref="MaskingTechnique"/>, as per proposal §3.3.
    /// The Masking Engine uses this as the baseline; a runtime policy can
    /// substitute individual entries.
    /// </summary>
    public static readonly IReadOnlyDictionary<SensitiveDataType, MaskingRule> Defaults =
        new Dictionary<SensitiveDataType, MaskingRule>
        {
            // PII
            [SensitiveDataType.FullName]               = R(SensitiveDataType.FullName,               MaskingTechnique.Partial,          "Reveal first initial only"),
            [SensitiveDataType.NationalId]             = R(SensitiveDataType.NationalId,             MaskingTechnique.Full,             "Fully redact NID"),
            [SensitiveDataType.PassportNumber]         = R(SensitiveDataType.PassportNumber,         MaskingTechnique.Full,             "Fully redact passport number"),
            [SensitiveDataType.DriverLicence]          = R(SensitiveDataType.DriverLicence,          MaskingTechnique.Full,             "Fully redact driver licence"),
            [SensitiveDataType.DateOfBirth]            = R(SensitiveDataType.DateOfBirth,            MaskingTechnique.Partial,          "Reveal year only"),
            [SensitiveDataType.Address]                = R(SensitiveDataType.Address,                MaskingTechnique.Partial,          "Reveal city/country; mask street"),
            [SensitiveDataType.EmailAddress]           = R(SensitiveDataType.EmailAddress,           MaskingTechnique.Partial,          "Mask local part; keep domain"),
            [SensitiveDataType.PhoneNumber]            = R(SensitiveDataType.PhoneNumber,            MaskingTechnique.SuffixPreserving, "Keep last 4 digits"),

            // Financial
            [SensitiveDataType.CreditCardNumber]       = R(SensitiveDataType.CreditCardNumber,       MaskingTechnique.SuffixPreserving, "Keep last 4 digits (PCI-DSS compliant)"),
            [SensitiveDataType.BankAccountNumber]      = R(SensitiveDataType.BankAccountNumber,      MaskingTechnique.SuffixPreserving, "Keep last 4 digits"),
            [SensitiveDataType.SwiftBic]               = R(SensitiveDataType.SwiftBic,               MaskingTechnique.Partial,          "Reveal bank & country code only"),
            [SensitiveDataType.Iban]                   = R(SensitiveDataType.Iban,                   MaskingTechnique.SuffixPreserving, "Keep last 4 chars"),
            [SensitiveDataType.TaxIdNumber]            = R(SensitiveDataType.TaxIdNumber,            MaskingTechnique.Full,             "Fully redact tax ID"),

            // Credentials
            [SensitiveDataType.Password]               = R(SensitiveDataType.Password,               MaskingTechnique.Full,             "Fully redact password"),
            [SensitiveDataType.ApiKey]                 = R(SensitiveDataType.ApiKey,                 MaskingTechnique.TokenPreserving,  "Replace with format-preserving token"),
            [SensitiveDataType.AuthToken]              = R(SensitiveDataType.AuthToken,              MaskingTechnique.TokenPreserving,  "Replace with format-preserving token"),
            [SensitiveDataType.PrivateKey]             = R(SensitiveDataType.PrivateKey,             MaskingTechnique.Full,             "Fully redact private key material"),
            [SensitiveDataType.ConnectionString]       = R(SensitiveDataType.ConnectionString,       MaskingTechnique.PatternBased,     "Mask credential fields; preserve structure"),

            // Network
            [SensitiveDataType.IpAddress]              = R(SensitiveDataType.IpAddress,              MaskingTechnique.PatternBased,     "Replace last octet with 0"),
            [SensitiveDataType.MacAddress]             = R(SensitiveDataType.MacAddress,             MaskingTechnique.CharacterLevel,   "Mask all hex digits"),
            [SensitiveDataType.Url]                    = R(SensitiveDataType.Url,                    MaskingTechnique.Partial,          "Reveal scheme+host; mask path/query"),
            [SensitiveDataType.SshFingerprint]         = R(SensitiveDataType.SshFingerprint,         MaskingTechnique.Full,             "Fully redact SSH fingerprint"),

            // Organisational
            [SensitiveDataType.ProjectCodename]        = R(SensitiveDataType.ProjectCodename,        MaskingTechnique.PatternBased,     "Replace with synthetic codename"),
            [SensitiveDataType.ConfidentialFinancialData] = R(SensitiveDataType.ConfidentialFinancialData, MaskingTechnique.Full,      "Fully redact confidential figures"),
            [SensitiveDataType.HrRecord]               = R(SensitiveDataType.HrRecord,               MaskingTechnique.Full,             "Fully redact HR record"),
            [SensitiveDataType.SourceCode]             = R(SensitiveDataType.SourceCode,             MaskingTechnique.PatternBased,     "Replace identifiers with placeholders"),
            [SensitiveDataType.InternalDomainName]     = R(SensitiveDataType.InternalDomainName,     MaskingTechnique.PatternBased,     "Replace with generic internal.domain"),
        };

    // Factory helper to keep Defaults initialisation concise.
    private static MaskingRule R(SensitiveDataType dt, MaskingTechnique t, string desc) =>
        new() { DataType = dt, Technique = t, Description = desc };

    /// <inheritdoc />
    public override string ToString() =>
        $"{DataType} → {Technique}" + (Description is null ? "" : $" ({Description})");
}
