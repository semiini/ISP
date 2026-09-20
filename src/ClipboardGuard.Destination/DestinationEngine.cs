namespace ClipboardGuard.Destination;

// Task 6 — Destination Analysis Engine
// Implement per proposal §3.4 / Fig. 4 and README Task 6.
//
// This module must:
//  1. Call user32.dll GetForegroundWindow / GetWindowThreadProcessId to detect
//     the foreground application at paste-time.
//  2. Classify the app into a DestinationCategory:
//       Trusted, Local, External, Ai, Unknown
//  3. Return a populated ClipboardGuard.Core.Models.DestinationInfo.
//  4. Combine source risk + detection risk + destination category to produce
//     a ClipboardGuard.Core.Models.PolicyDecision.
//  5. Unit tests live in tests/ClipboardGuard.Destination.Tests.
