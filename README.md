# ClipboardGuard

**Source-Aware & Destination-Aware Clipboard Protection System**

IE3092 – Information Security Project · Group 09 · SLIIT B.Sc.(Hons) IT, Year 3 Semester 2

A Windows desktop application that sits between the clipboard and the applications using it.
When you copy something sensitive, ClipboardGuard masks it immediately; when you paste it, it
tells you where the data is going and lets you decide what actually gets inserted.

---

## The problem

Copy-paste is the most common way confidential data leaves an organisation, and it is almost
entirely unmonitored. A developer copies a connection string from an IDE and pastes it into an AI
chat window. Someone copies a customer record from an internal system into a personal email. The
clipboard does not care where data came from or where it is going — it just carries it.

ClipboardGuard adds that awareness. It identifies the **source** application, detects **sensitive
content**, **masks** it, identifies the **destination** application, and then puts the decision in
the hands of the user instead of silently allowing or silently blocking.

---

## How it works

```
Copy (Ctrl+C)
   │
   ▼
[1] Source Identification ──▶ [2] Sensitive Data Detection
   │                                     │
   ▼                                     ▼
        [3] Masking + Clipboard Update  (clipboard now holds the masked value)
                       │
                       ▼
Paste (Ctrl+V)  ──▶  [4] Destination Analysis
                       │
                       ▼
        ┌──────────────┴──────────────┐
        │  Paste original             │
        │  Paste redacted             │   ← the user chooses
        │  Cancel                     │
        └──────────────┬──────────────┘
                       ▼
               Log to SQLite
```

**On copy**, the active window is identified, the text is scanned for sensitive data, and anything
found is masked on the clipboard straight away. The protected value is in place before any
application can read it — this is what makes cancelling free later, because the safe version is
already the one sitting on the clipboard.

**On paste**, the keystroke is intercepted before it reaches the target application. ClipboardGuard
identifies the destination, then asks:

| Choice | What is inserted | Clipboard afterwards |
|---|---|---|
| **Paste original** | The real value | Re-masked after ~300 ms |
| **Paste redacted** | The masked value | Unchanged (masked) |
| **Cancel** | Nothing | Unchanged (masked) — your copy survives |

Every outcome is written to a local SQLite log. **The raw sensitive value is never logged or
written to disk** — only the masked form, the data types found, and the decision.

---

## What it detects

26 categories of sensitive data across five groups, matched by 27 pattern rules with format
validation (Luhn for payment cards, IBAN checksum) to suppress false positives:

| Group | Examples |
|---|---|
| **PII** | Full name, national ID / SSN / NIC, passport, driving licence, date of birth, address, email, phone |
| **Financial** | Payment card, bank account, IBAN, SWIFT/BIC, tax ID |
| **Credentials** | Passwords, API keys, bearer/JWT tokens, private keys, connection strings |
| **Network** | IPv4/IPv6, MAC address, internal URLs, SSH fingerprints |
| **Organisational** | Project codenames, confidential financials, HR records, source code, internal domains |

## How it masks

Six techniques, applied per data type:

| Technique | Example input | Example output |
|---|---|---|
| Full | any value | `***REDACTED***` |
| Partial | `john@example.com` | `jo**@example.com` |
| Character-level | an 11-character value | `***********` |
| Suffix-preserving | `4111111111111234` | `************1234` |
| Token-preserving | any value | a stable token — the same input always maps to the same token |
| Pattern-based | `951234567V` · `192.168.1.45` | `999999999V` · `192.168.1.0` |

## How it classifies applications

**Sources** are classified by process name, executable path and Authenticode publisher:

| Source category | Risk | Examples |
|---|---|---|
| Trusted | Low | Windows shell, system utilities |
| Business | Medium | Office, browsers, Teams, Slack |
| Development | High | IDEs, terminals, database and API tools |
| Credential | Critical | KeePass, 1Password, Bitwarden |
| Unknown | Medium | anything unmatched |

**Destinations** additionally use the window title, so a browser is judged by the site it is on:

| Destination category | Risk | Examples |
|---|---|---|
| Trusted | Low | Internal/intranet tools and corporate apps |
| Local | Medium | Editors, word processors, local database clients |
| External | High | Browsers on public sites, email, chat, FTP/SCP |
| AI | Critical | ChatGPT, Claude, Copilot, Gemini, Perplexity — desktop apps *or* browser tabs |
| Unknown | High | unidentifiable; treated as External |

## The policy matrix

Source risk, detected-data risk and destination category combine into a recommendation. Since the
user always gets the final say, the recommendation now selects which button is **pre-selected** in
the prompt, so the safe answer is the default exactly where policy is strictest.

```
destination \ data risk  │  Low      Medium    High      Critical
─────────────────────────┼──────────────────────────────────────────
Trusted                  │  Allow    Allow     Allow     Mask
Local                    │  Allow    Allow     Mask      Confirm
External / Unknown       │  Allow    Mask      Confirm   Block
AI                       │  Mask     Confirm   Block     Block
```

Clean content is always allowed. Content copied from a **credential manager** is escalated one risk
level for every destination except a trusted internal one.

---

## Requirements

- Windows 10 or 11
- [.NET SDK 10](https://dotnet.microsoft.com/download) — `global.json` pins `10.0.100` with
  `rollForward: latestMinor`, so any 10.0.x SDK works
- No database server needed; SQLite is file-based and created on first run

## Setup and run

```bash
git clone <repository-url>
cd ISP
dotnet restore
dotnet build
dotnet run --project src/ClipboardGuard.App
```

For a demo, build once and launch the executable directly:

```bash
dotnet build -c Release
src/ClipboardGuard.App/bin/Release/net10.0-windows/ClipboardGuard.App.exe
```

In Visual Studio: open `ClipboardGuard.sln`, set **ClipboardGuard.App** as the startup project, F5.

### What to expect on launch

**No window opens.** ClipboardGuard is a tray application — look for the shield icon in the system
tray, expanding the hidden-icons chevron (`^`) if necessary. `dotnet run` will not return to the
prompt until you exit the app; that is normal, not a hang.

- **Double-click** the tray icon, or right-click → **Settings**, to open settings
- Right-click → **View event log** for recent decisions
- Right-click → **Exit** to quit — this is the only way to stop it cleanly

Only one instance can run at a time. Launching a second shows a notice and exits, because two
instances would install two keyboard hooks and prompt you twice for one paste.

### Try it

1. In Notepad, type and copy this line:

   ```
   Card charged: 4000 0012 3456 7899 expires 12/28.
   ```

2. A tray notification confirms the copy was masked. Paste anywhere (`Ctrl+V`) — the prompt appears,
   naming the source, the destination and the data type found.
3. Try each button. **Paste redacted** inserts `**** **** **** 7899`; **Paste original** inserts the
   real number and then re-masks the clipboard behind you; **Cancel** inserts nothing and leaves your
   copy intact.
4. Repeat the paste into a browser to see the destination classification change.
5. Right-click the tray icon → **View event log** to see all three decisions recorded.

---

## Settings

Double-click the tray icon:

- **Protection enabled** — master switch; when off, the clipboard is left completely untouched
- **Show tray alerts** — the balloon shown when a copy is masked
- **Protected data types** — enable or disable any of the 26 categories individually

Settings apply immediately and live in memory for the session; they are not yet persisted between
runs.

## Where your data lives

| What | Where |
|---|---|
| Event log (SQLite) | `%LOCALAPPDATA%\ClipboardGuard\clipboard_guard.db` |
| Raw sensitive text | Memory only, for at most 5 minutes after the copy — never written to disk |

---

## Repository layout

```
ISP/
├── src/
│   ├── ClipboardGuard.Core/          Shared contracts and models (no logic)
│   ├── ClipboardGuard.SourceId/      Source identification — user32.dll + classification
│   ├── ClipboardGuard.Detection/     Pattern library, validators, detection engine
│   ├── ClipboardGuard.Masking/       Six masking techniques + clipboard writer
│   ├── ClipboardGuard.Destination/   Destination classification + policy evaluation
│   ├── ClipboardGuard.Data/          SQLite schema and EventLogger
│   ├── ClipboardGuard.UI/            Tray icon, paste prompt, settings screen
│   └── ClipboardGuard.App/           Composition root, clipboard + paste hooks, pipeline
├── tests/
│   ├── ClipboardGuard.SourceId.Tests/
│   ├── ClipboardGuard.Detection.Tests/
│   ├── ClipboardGuard.Masking.Tests/
│   └── ClipboardGuard.Destination.Tests/
├── docs/
│   ├── build-spec.md                 Module boundaries, build order, coding constraints
│   ├── architecture.md
│   └── evaluation-results.md
├── ClipboardGuard.sln
└── global.json
```

Each module maps to one section of the project proposal:

| Module | Proposal reference |
|---|---|
| `ClipboardGuard.SourceId` | §3.1, Fig. 1 — source classification |
| `ClipboardGuard.Detection` | §3.2, Fig. 2 — sensitive data categories |
| `ClipboardGuard.Masking` | §3.3, Fig. 3 — masking approaches |
| `ClipboardGuard.Destination` | §3.4, Fig. 4 — destination classification |
| `ClipboardGuard.Data` | §3.3 — clipboard management / logging |
| `ClipboardGuard.UI` | §4 — UI framework |
| `ClipboardGuard.App` | §4.4 — process flow |

## Tech stack

| Component | Technology |
|---|---|
| Language / framework | C# on .NET 10 |
| UI | Windows Forms (`NotifyIcon`, `TaskDialog`) |
| Clipboard, window and keyboard access | WinAPI via `user32.dll` |
| Pattern matching | `System.Text.RegularExpressions` |
| Storage | SQLite (`Microsoft.Data.Sqlite`) |
| Serialisation | Newtonsoft.Json 13.0 |
| Tests | xUnit |

## Testing

```bash
dotnet test
```

191 tests across four projects:

| Project | Tests | Covers |
|---|---:|---|
| `ClipboardGuard.SourceId.Tests` | 75 | Source classification and risk mapping |
| `ClipboardGuard.Destination.Tests` | 52 | Destination classification and the policy matrix |
| `ClipboardGuard.Detection.Tests` | 46 | Pattern accuracy over sensitive and clean datasets |
| `ClipboardGuard.Masking.Tests` | 18 | All six masking techniques plus SQLite logging |

---

## Design notes

**Masking happens on copy, not on paste.** The clipboard holds the protected value from the moment
you press Ctrl+C. Pasting the original is an explicit, logged, temporary reveal rather than the
default state.

**Paste is detected by intercepting the keystroke.** A low-level keyboard hook (`WH_KEYBOARD_LL`)
catches Ctrl+V and Shift+Insert, swallows the keystroke, prompts, and then replays the paste into
the original window. The hook procedure itself only reads an in-memory flag and posts a message —
Windows silently removes any low-level hook whose callback exceeds roughly 300 ms, so all real work
happens after it returns. The original proposal specified detecting a foreground-window change
instead; that fires when you switch windows rather than when you paste, which prompts for pastes
that never happen.

**Core contracts are shared, never duplicated.** Every module imports its models from
`ClipboardGuard.Core`. The three prompt outcomes map onto the existing `PolicyDecision` values
(`Allow` / `Mask` / `Block`) rather than extending the enum.

## Known limitations

- **Elevated windows.** A non-elevated keyboard hook cannot see keystrokes sent to an
  administrator-elevated application, so pastes there are not intercepted. Running ClipboardGuard
  as administrator resolves this.
- **Antivirus / EDR.** A global keyboard hook combined with synthetic keystrokes resembles keylogger
  behaviour and some endpoint protection products will flag it.
- **Paste replay.** Keystroke re-injection is reliable in standard Win32, WinForms and WPF targets;
  some Chromium/Electron surfaces and remote-desktop sessions may need tuning of the focus-settle
  delay in `PasteInterceptor`.
- **Reveal window.** After choosing *Paste original*, the real value is on the clipboard for about
  300 ms. An application actively polling the clipboard in that window could read it.
- **Text only.** Images, files and rich-text clipboard formats pass through unexamined.
- **Settings are not persisted** between runs.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Terminal appears frozen after `dotnet run` | Expected — the tray app runs until you exit it. Use tray → Exit, or Ctrl+C. |
| No window appears | By design. The shield icon is in the system tray, possibly under the `^` chevron. |
| "Already running" message | Another instance is live. Exit it from the tray first. |
| Prompt stops appearing after heavy use | Windows removed the keyboard hook after a slow callback. Restart the app. |
| Paste does nothing in one specific app | Keystroke replay was not accepted; increase `FocusSettleMs` in `PasteInterceptor`. |
| Clipboard seems stuck masked | Expected after Cancel. Copy again, or disable protection in Settings. |

## Project status

The eight modules, the pipeline and the test suite are complete and building cleanly.
`docs/architecture.md` and `docs/evaluation-results.md` are still placeholder templates awaiting the
Task 9 evaluation figures (detection accuracy, false positive/negative rates, classification
accuracy, end-to-end latency) and the final architecture write-up.
