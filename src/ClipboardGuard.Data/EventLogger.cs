namespace ClipboardGuard.Data;

// Task 5 — SQLite Event Logging
// Implement per proposal §3.3 (clipboard management) and README Task 5.
//
// This module must:
//  1. Design and create the SQLite schema for ClipboardEvent storage.
//  2. Implement EventLogger with methods:
//       - Task LogAsync(ClipboardEvent evt)
//       - Task<IReadOnlyList<ClipboardEvent>> QueryAsync(...)
//  3. Use Microsoft.Data.Sqlite for all database access.
//  4. Never store raw sensitive text — only the maskedText field from ClipboardEvent.
