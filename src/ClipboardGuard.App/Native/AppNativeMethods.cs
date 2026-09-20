using System.Runtime.InteropServices;

namespace ClipboardGuard.App.Native;

/// <summary>
/// P/Invoke declarations used by the composition root to observe the clipboard
/// and the foreground window (proposal §4.4 — pipeline triggers).
/// </summary>
internal static class AppNativeMethods
{
    // ── Messages ─────────────────────────────────────────────────────────────

    /// <summary>Posted to every clipboard-format listener when clipboard content changes.</summary>
    internal const int WM_CLIPBOARDUPDATE = 0x031D;

    /// <summary>Message-only window parent handle (HWND_MESSAGE).</summary>
    internal static readonly IntPtr HWND_MESSAGE = new(-3);

    // ── WinEvent constants (foreground-change = paste trigger) ───────────────

    internal const uint EVENT_SYSTEM_FOREGROUND   = 0x0003;
    internal const uint WINEVENT_OUTOFCONTEXT     = 0x0000;
    internal const uint WINEVENT_SKIPOWNPROCESS   = 0x0002;

    // ── Clipboard monitoring ─────────────────────────────────────────────────

    /// <summary>
    /// Registers <paramref name="hwnd"/> to receive <see cref="WM_CLIPBOARDUPDATE"/>
    /// whenever clipboard content changes.
    /// </summary>
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AddClipboardFormatListener(IntPtr hwnd);

    /// <summary>Removes a window previously registered with <see cref="AddClipboardFormatListener"/>.</summary>
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    // ── Foreground-window monitoring ─────────────────────────────────────────

    /// <summary>Callback signature for <see cref="SetWinEventHook"/>.</summary>
    internal delegate void WinEventProc(
        IntPtr hWinEventHook, uint eventType, IntPtr hwnd,
        int idObject, int idChild, uint dwEventThread, uint dwmsEventTime);

    /// <summary>
    /// Installs an out-of-context hook that reports foreground-window changes on the
    /// installing thread's message loop.
    /// </summary>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern IntPtr SetWinEventHook(
        uint eventMin, uint eventMax, IntPtr hmodWinEventProc,
        WinEventProc lpfnWinEventProc, uint idProcess, uint idThread, uint dwFlags);

    /// <summary>Removes a hook installed by <see cref="SetWinEventHook"/>.</summary>
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnhookWinEvent(IntPtr hWinEventHook);

    /// <summary>Resolves the process that owns a window.</summary>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
