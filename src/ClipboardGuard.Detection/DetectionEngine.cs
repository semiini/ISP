namespace ClipboardGuard.Detection;

// Task 3 — Sensitive Data Detection Engine
// Implement per proposal §3.2 / Fig. 2 and README Task 3.
//
// This module must:
//  1. Accept a ClipboardGuard.Core.Models.ClipboardContent instance.
//  2. Run a regex/pattern library covering ALL SensitiveDataType categories:
//       PII, Financial, Credentials, Network, Organisational Information.
//  3. For each match record: DataType, StartIndex, Length, RiskLevel.
//     — Do NOT store the matched text itself (README constraint §3.2).
//  4. Return a populated ClipboardGuard.Core.Models.DetectionResult.
//  5. Unit tests live in tests/ClipboardGuard.Detection.Tests.
