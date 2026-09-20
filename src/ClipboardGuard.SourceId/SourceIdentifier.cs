namespace ClipboardGuard.SourceId;

// Task 2 — Source Identification Module
// Implement per proposal §3.1 / Fig. 1 and README Task 2.
//
// This module must:
//  1. Call user32.dll GetForegroundWindow / GetWindowThreadProcessId to detect the
//     active window at copy-time.
//  2. Read the process name, exe path, and window title from the resulting HWND.
//  3. Verify the executable's Authenticode signature to obtain the publisher name.
//  4. Classify the process into a SourceCategory (Trusted/Business/Development/Credential/Unknown).
//  5. Assign a RiskLevel based on the category and any additional heuristics.
//  6. Return a populated ClipboardGuard.Core.Models.SourceInfo.
