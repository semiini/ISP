namespace ClipboardGuard.Masking;

// Task 4 — Data Masking & Clipboard Management Engine
// Implement per proposal §3.3 / Fig. 3 and README Task 4.
//
// This module must:
//  1. Accept a ClipboardContent + DetectionResult + a set of MaskingRules.
//  2. Implement ALL six MaskingTechnique variants exactly matching the
//     worked examples in the proposal §3.3 masking approaches table:
//       Full, Partial, CharacterLevel, SuffixPreserving, TokenPreserving, PatternBased
//  3. Apply each rule to its matching text span in RawText.
//  4. Write the masked content back to the Windows clipboard (user32.dll).
//  5. Return the masked text string (stored in ClipboardEvent.MaskedText).
//  6. Unit tests live in tests/ClipboardGuard.Masking.Tests.
