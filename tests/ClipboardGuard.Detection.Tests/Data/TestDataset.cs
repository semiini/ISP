using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Detection.Tests.Data;

/// <summary>
/// Curated dataset containing sensitive samples for each of the 27 <see cref="SensitiveDataType"/> categories
/// and non-sensitive / clean samples to evaluate true-positive and true-negative detection rates.
/// </summary>
public static class TestDataset
{
    public sealed record SampleEntry(SensitiveDataType DataType, string SampleText, RiskLevel ExpectedRisk);

    /// <summary>
    /// Sensitive true-positive samples covering all 27 categories across PII, Financial, Credentials, Network, and Org Info.
    /// </summary>
    public static readonly IReadOnlyList<SampleEntry> SensitiveSamples =
    [
        // PII
        new(SensitiveDataType.EmailAddress, "Please reply to john.doe@cyberguard-corp.com as soon as possible.", RiskLevel.Medium),
        new(SensitiveDataType.PhoneNumber, "Call my direct office line at +1 (555) 867-5309 today.", RiskLevel.Medium),
        new(SensitiveDataType.NationalId, "Customer SSN is 123-45-6789.", RiskLevel.High),
        new(SensitiveDataType.NationalId, "Applicant NIC: 951234567V submitted today.", RiskLevel.High),
        new(SensitiveDataType.PassportNumber, "Passport Number: A1234567 verified.", RiskLevel.High),
        new(SensitiveDataType.DriverLicence, "Driver License: D12345678 issued by state.", RiskLevel.High),
        new(SensitiveDataType.DateOfBirth, "Date of Birth: 1990-05-15 recorded.", RiskLevel.Medium),
        new(SensitiveDataType.Address, "Deliver the parcel to 742 Evergreen Terrace, Springfield, OR 97477.", RiskLevel.Medium),
        new(SensitiveDataType.FullName, "Full Name: Alice Montgomery will attend.", RiskLevel.Medium),

        // Financial
        new(SensitiveDataType.CreditCardNumber, "Card charged: 4000 0012 3456 7899 expires 12/28.", RiskLevel.High),
        new(SensitiveDataType.Iban, "Transfer funds to IBAN DE89 3704 0044 0532 0130 00 immediately.", RiskLevel.High),
        new(SensitiveDataType.SwiftBic, "Bank routing BIC: DEUTDEDBFXX", RiskLevel.High),
        new(SensitiveDataType.BankAccountNumber, "Direct deposit Account Number: 9876543210123", RiskLevel.High),
        new(SensitiveDataType.TaxIdNumber, "Federal Tax ID: 12-3456789", RiskLevel.High),

        // Credentials
        new(SensitiveDataType.Password, "Initial admin login: password = MyS3cur3P@ssw0rd!#", RiskLevel.Critical),
        new(SensitiveDataType.ApiKey, "Deployment key is AKIAIOSFODNN7EXAMPLE for AWS.", RiskLevel.Critical),
        new(SensitiveDataType.ApiKey, "Personal access token: ghp_1234567890abcdefghijklmnopqrstuvwxyz", RiskLevel.Critical),
        new(SensitiveDataType.AuthToken, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", RiskLevel.Critical),
        new(SensitiveDataType.PrivateKey, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3XYZ\n-----END RSA PRIVATE KEY-----", RiskLevel.Critical),
        new(SensitiveDataType.ConnectionString, "Data Source=sqlserver.corp.local;Initial Catalog=HRDb;User Id=dbadmin;Password=SecretDbPassword123;", RiskLevel.Critical),

        // Network
        new(SensitiveDataType.IpAddress, "Production server host located at 192.168.10.45 in subnet.", RiskLevel.Medium),
        new(SensitiveDataType.MacAddress, "Network adapter MAC: 00:1A:2B:3C:4D:5E bound.", RiskLevel.Medium),
        new(SensitiveDataType.Url, "Check dashboard at https://intranet.company.com/admin/settings?ref=copy", RiskLevel.Low),
        new(SensitiveDataType.SshFingerprint, "Host fingerprint SHA256:uTf03/4p11w9Y4r9G+oZ0e0gVq2FzYx2mJz9Pz/AbCdEf=", RiskLevel.High),

        // Organisational Information
        new(SensitiveDataType.ProjectCodename, "Initiating Phase 2 of Project Chimera immediately.", RiskLevel.Medium),
        new(SensitiveDataType.ConfidentialFinancialData, "Confidential: Q3 Revenue $45.8 million exceeded expectations.", RiskLevel.High),
        new(SensitiveDataType.HrRecord, "Record updated: Employee ID: EMP-89421", RiskLevel.High),
        new(SensitiveDataType.SourceCode, "public class SecurityGateway { private readonly string _key; }", RiskLevel.High),
        new(SensitiveDataType.InternalDomainName, "Connect via internal proxy at database.internal.corp", RiskLevel.Medium)
    ];

    /// <summary>
    /// Clean non-sensitive samples that must produce 0 detections (True Negatives).
    /// </summary>
    public static readonly IReadOnlyList<string> NonSensitiveSamples =
    [
        "Good morning everyone! Let's sync at 2 PM for our daily standup.",
        "The quick brown fox jumps over the lazy dog.",
        "# Architecture Overview\n\nThis application is built with modern clean architecture principles.",
        "Order details: 3 apples, 5 oranges, 2 packs of whole milk.",
        "Please review the attached PDF report before tomorrow's executive presentation.",
        "The meeting has been rescheduled to Thursday at noon in Room 304.",
        "Version 2.4.0 release notes: performance improvements and bug fixes.",
        "This project adheres to semantic versioning standards."
    ];
}
