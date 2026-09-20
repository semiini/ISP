using System.Runtime.InteropServices;

namespace ClipboardGuard.App.Native;

/// <summary>
/// P/Invoke declarations used by the composition root to observe the clipboard and to
/// intercept and replay paste keystrokes (proposal §4.4 — pipeline triggers).
/// </summary>
internal static class AppNativeMethods
{
    // ── Clipboard listener ───────────────────────────────────────────────────

    /// <summary>Posted to every clipboard-format listener when clipboard content changes.</summary>
    internal const int WM_CLIPBOARDUPDATE = 0x031D;

    /// <summary>Message-only window parent handle (HWND_MESSAGE).</summary>
    internal static readonly IntPtr HWND_MESSAGE = new(-3);

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

    // ── Low-level keyboard hook (paste interception) ─────────────────────────

    internal const int WH_KEYBOARD_LL = 13;
    internal const int WM_KEYDOWN     = 0x0100;
    internal const int WM_SYSKEYDOWN  = 0x0104;

    /// <summary>Set in KBDLLHOOKSTRUCT.flags when the event came from SendInput/keybd_event.</summary>
    internal const uint LLKHF_INJECTED = 0x10;

    internal const int VK_SHIFT   = 0x10;
    internal const int VK_CONTROL = 0x11;
    internal const int VK_INSERT  = 0x2D;
    internal const int VK_V       = 0x56;

    /// <summary>Contents of the lParam passed to a <see cref="WH_KEYBOARD_LL"/> hook.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct KBDLLHOOKSTRUCT
    {
        internal uint vkCode;
        internal uint scanCode;
        internal uint flags;
        internal uint time;
        internal IntPtr dwExtraInfo;
    }

    /// <summary>Callback signature for a low-level keyboard hook.</summary>
    internal delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    /// <summary>
    /// Installs a global low-level keyboard hook. The callback is delivered on the message
    /// loop of the installing thread and must return quickly — Windows silently removes a
    /// hook whose procedure exceeds LowLevelHooksTimeout (~300 ms by default).
    /// </summary>
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr SetWindowsHookEx(
        int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnhookWindowsHookEx(IntPtr hhk);

    /// <summary>Passes a hook event on to the next hook in the chain.</summary>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr GetModuleHandle(string? lpModuleName);

    /// <summary>High-order bit is set while the key is physically down.</summary>
    [DllImport("user32.dll")]
    internal static extern short GetAsyncKeyState(int vKey);

    // ── Paste replay ─────────────────────────────────────────────────────────

    internal const uint KEYEVENTF_KEYUP = 0x0002;

    /// <summary>
    /// Synthesises a keystroke. Events injected this way carry
    /// <see cref="LLKHF_INJECTED"/>, which is how our own replayed paste avoids
    /// re-entering the hook.
    /// </summary>
    // ponytail: keybd_event, switch to SendInput if injection proves unreliable.
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    // ── Window helpers ───────────────────────────────────────────────────────

    [DllImport("user32.dll", SetLastError = false)]
    internal static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetForegroundWindow(IntPtr hWnd);

    /// <summary>
    /// Queues a message without waiting — used to hand work from the hook procedure to the
    /// message loop so the hook itself returns immediately.
    /// </summary>
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
}
