# Architecture Notes

> **Placeholder** — fill in during Task 10 (Final Documentation).

## Pipeline Overview

```
Copy (Ctrl+C)
   │
   ▼
[1] Source Identification  ──▶  [2] Sensitive Data Detection
   │                                     │
   ▼                                     ▼
        [3] Data Masking & Clipboard Management
                       │
                       ▼
              [4] Destination Analysis
                       │
                       ▼
        Allow / Mask / Block / Confirm  +  Log to SQLite
```

## Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `ClipboardGuard.Core` | Shared contracts / models |
| `ClipboardGuard.SourceId` | Active-window detection & source classification |
| `ClipboardGuard.Detection` | Regex-based sensitive data detection |
| `ClipboardGuard.Masking` | Apply masking techniques to clipboard content |
| `ClipboardGuard.Destination` | Foreground-app detection & destination classification |
| `ClipboardGuard.Data` | SQLite event logging |
| `ClipboardGuard.UI` | Windows Forms tray icon, alerts, settings |
| `ClipboardGuard.App` | Pipeline orchestration & clipboard hook |
