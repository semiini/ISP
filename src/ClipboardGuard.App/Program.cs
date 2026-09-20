namespace ClipboardGuard.App;

// Task 8 — Pipeline Integration / Composition Root
// Implement per proposal §4.4 process-flow diagram and README Task 8.
//
// This is the application entry point. It must:
//  1. Hook the Windows clipboard via user32.dll AddClipboardFormatListener.
//  2. On WM_CLIPBOARDUPDATE:
//       a. Invoke SourceIdentifier  → SourceInfo
//       b. Build ClipboardContent
//       c. Invoke DetectionEngine   → DetectionResult
//       d. Resolve MaskingRules
//       e. Invoke MaskingEngine     → maskedText (+ write back to clipboard)
//  3. On paste detection (foreground-window change after copy):
//       a. Invoke DestinationEngine → DestinationInfo + PolicyDecision
//       b. Execute Allow/Block/Confirm action
//       c. Invoke EventLogger       → persist ClipboardEvent
//       d. Notify UI
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // Placeholder entry point — will be implemented in Task 8.
    }
}
