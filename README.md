# Source-Aware & Destination-Aware Clipboard Protection System

**Module:** IE3092 – Information Security Project | **Group:** 09 | **SLIIT — B.Sc.(Hons) IT, Year 3 Sem 2**

> **This file is context for an AI coding assistant, not a human onboarding doc.** It defines
> the project spec, the module boundaries, the build order, and the rules the assistant must
> follow while working in this repo. If you're a human team member looking for git commands and
> example prompts, use `TEAM_GUIDE.md` instead.

---

## 1. What we're building

A Windows desktop application that sits between the clipboard and the user. Every copy/paste
goes through four stages before it's allowed through:

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

Full rationale, detection categories, masking rules and destination policy tables are in
`docs/proposal.pdf` — treat that document as the spec of record for any behavior not fully
described here. This README only covers **module boundaries and build order**.

---

## 2. Constraints for the AI tool (read before touching any code)

- **Single branch only.** This repo uses `main` exclusively — never create, switch to, or
  suggest a feature branch, and never propose a pull request. Assume all work commits directly
  to `main`.
- **Stay inside the current task's scope.** Each task below names an exact folder (or folders).
  Only create/edit files inside that folder and its matching test project, unless the prompt
  explicitly asks you to touch something else.
- **Shared types live only in `ClipboardGuard.Core`.** Never redefine or duplicate a contract
  (`SourceInfo`, `DetectionResult`, etc.) inside a module project — import it from Core.
- **Never persist or log a raw sensitive value beyond the detection step.** Per proposal §3.2,
  `DetectionResult` should carry data type / position / risk level, not the matched sensitive
  text itself, once masking has occurred.
- **Match the proposal's tables exactly.** The masking techniques (§3.3), source categories
  (§3.1), destination categories (§3.4) and sensitive data categories (§3.2) are fixed — don't
  invent your own categories, thresholds, or masking formats.
- **Before declaring a task done, run it yourself:**
  ```
  dotnet build
  dotnet test
  ```
  Fix any failures before handing control back. Don't leave a broken build for the next task.

---

## 3. Task → module mapping

Every task below maps to exactly one module folder, so two tasks never touch the same files.

| Task | Module / deliverable | Folder(s) | Spec reference |
|---|---|---|---|
| 0 | Project scaffolding | whole repo skeleton | §3 (this doc) |
| 1 | Shared data contracts | `ClipboardGuard.Core` | §3.1–§3.4 (all engines) |
| 2 | Source Identification Module | `ClipboardGuard.SourceId` | proposal §3.1, Fig. 1 |
| 3 | Sensitive Data Detection Engine | `ClipboardGuard.Detection` | proposal §3.2, Fig. 2 |
| 4 | Data Masking & Clipboard Management Engine | `ClipboardGuard.Masking` | proposal §3.3, Fig. 3 |
| 5 | SQLite event logging | `ClipboardGuard.Data` | proposal §3.3 (clipboard management) |
| 6 | Destination Analysis Engine | `ClipboardGuard.Destination` | proposal §3.4, Fig. 4 |
| 7 | Windows Forms UI | `ClipboardGuard.UI` | proposal §4 (UI Framework) |
| 8 | Pipeline integration | `ClipboardGuard.App` | proposal §4.4 process-flow diagram |
| 9 | Testing & evaluation | `tests/`, `docs/evaluation-results.md` | proposal evaluation criteria (§3.2, main objectives) |
| 10 | Final documentation | `docs/`, `README.md` | — |

---

## 4. Repository structure

```
clipboard-guard/
├── src/
│   ├── ClipboardGuard.Core/              # shared contracts/models
│   ├── ClipboardGuard.SourceId/          # Task 2
│   ├── ClipboardGuard.Detection/         # Task 3
│   ├── ClipboardGuard.Masking/           # Task 4
│   ├── ClipboardGuard.Destination/       # Task 6
│   ├── ClipboardGuard.Data/              # Task 5 — SQLite logging
│   ├── ClipboardGuard.UI/                # Task 7 — Windows Forms
│   └── ClipboardGuard.App/               # Task 8 — composition root / orchestrator
├── tests/
│   ├── ClipboardGuard.SourceId.Tests/
│   ├── ClipboardGuard.Detection.Tests/
│   ├── ClipboardGuard.Masking.Tests/
│   └── ClipboardGuard.Destination.Tests/
├── docs/
│   ├── proposal.pdf
│   ├── architecture.md
│   └── evaluation-results.md
├── .gitignore
└── README.md
```

---

## 5. Tech stack

| Component | Technology |
|---|---|
| Language | C# |
| Framework | .NET 10 |
| UI | Windows Forms |
| Clipboard access | WinAPI (`user32.dll`) |
| JSON | Newtonsoft.Json 13.0 |
| Storage | SQLite 3.0 |
| Pattern matching | `System.Text.RegularExpressions` |

---

## 6. Build order — tasks

Work through these in order; each depends on the shared contracts from Task 1, and later tasks
assume earlier ones are already in the repo and building cleanly.

### Task 0 — Project scaffolding
- [ ] Create the solution + empty projects matching §4
- [ ] Add `.gitignore` (Visual Studio / .NET template)
- [ ] Add `docs/proposal.pdf` and this README
- [ ] Add NuGet packages: `Newtonsoft.Json`, `Microsoft.Data.Sqlite`

### Task 1 — Shared data contracts (`ClipboardGuard.Core`)
Define these before any engine logic is written — every other task depends on them:
- [ ] `SourceInfo` — process name, PID, window title, exe path, publisher, category, risk level
- [ ] `ClipboardContent` — raw text, timestamp, source metadata
- [ ] `DetectionResult` — list of matches: data type, matched value position, risk level (no raw sensitive text)
- [ ] `MaskingRule` — data type → masking technique enum: `Full | Partial | CharacterLevel | SuffixPreserving | TokenPreserving | PatternBased`
- [ ] `DestinationInfo` — same shape as `SourceInfo`, for the paste target
- [ ] `PolicyDecision` enum — `Allow | Mask | Block | Confirm`
- [ ] `ClipboardEvent` — full record logged to SQLite: source + detections + decision + timestamps

### Task 2 — Source Identification Module (`ClipboardGuard.SourceId`)
Spec: proposal §3.1, Fig. 1, source classification table.
- [ ] Detect active window on copy via `user32.dll`
- [ ] Classify into Trusted / Business / Development / Credential categories
- [ ] Return a populated `SourceInfo`
- [ ] Unit tests in `ClipboardGuard.SourceId.Tests`

### Task 3 — Sensitive Data Detection Engine (`ClipboardGuard.Detection`)
Spec: proposal §3.2, Fig. 2, sensitive data categories table.
- [ ] Regex/pattern library covering all listed categories (PII, financial, credentials, network, org info)
- [ ] Return a populated `DetectionResult`
- [ ] Test dataset of sensitive + non-sensitive samples under `tests/`
- [ ] Unit tests in `ClipboardGuard.Detection.Tests`

### Task 4 — Data Masking & Clipboard Management Engine (`ClipboardGuard.Masking`)
Spec: proposal §3.3, Fig. 3, masking approaches table.
- [ ] Implement all 6 masking techniques exactly matching the worked examples in the table
- [ ] Write protected content back to the clipboard
- [ ] Unit tests in `ClipboardGuard.Masking.Tests`

### Task 5 — SQLite logging (`ClipboardGuard.Data`)
- [ ] Design the schema for `ClipboardEvent` storage
- [ ] Implement `EventLogger`

### Task 6 — Destination Analysis Engine (`ClipboardGuard.Destination`)
Spec: proposal §3.4, Fig. 4, destination classification table.
- [ ] Detect foreground app on paste
- [ ] Classify into Trusted / Local / External / AI / Unknown
- [ ] Return a `PolicyDecision`
- [ ] Unit tests in `ClipboardGuard.Destination.Tests`

### Task 7 — Windows Forms UI (`ClipboardGuard.UI`)
- [ ] Tray icon, alert popup, confirmation dialog, basic settings screen

### Task 8 — Integration (`ClipboardGuard.App`)
- [ ] Wire the four engines into the pipeline from proposal §4.4: copy → source ID → detection → masking → clipboard update → destination analysis → decision → log
- [ ] Hook clipboard monitoring via `user32.dll` (`AddClipboardFormatListener`)
- [ ] Wire the UI to the pipeline

### Task 9 — Testing & evaluation
Maps to the proposal's evaluation criteria: detection accuracy, false positive/negative rate,
masking effectiveness, source/destination classification accuracy, processing time.
- [ ] Detection accuracy/precision/recall results
- [ ] Masking-effectiveness results
- [ ] Source/destination classification accuracy results
- [ ] End-to-end latency benchmark
- [ ] Record all results in `docs/evaluation-results.md`

### Task 10 — Documentation
- [ ] Report section per module, matching §3 mapping
- [ ] Final architecture notes in `docs/architecture.md`
- [ ] Demo materials
