using System.Diagnostics;
using System.Runtime.InteropServices;
using ClipboardGuard.App.Native;

namespace ClipboardGuard.App;

/// <summary>
/// Turns a real paste keystroke into a pipeline event. A global low-level keyboard hook
/// watches for Ctrl+V / Shift+Insert; when a sensitive copy is pending the keystroke is
/// swallowed and handed to the message loop, which prompts the user and then replays the
/// paste with whatever they chose.
/// <para>
/// The hook procedure itself does almost nothing. Windows silently removes a low-level hook
/// whose callback exceeds <c>LowLevelHooksTimeout</c> (~300 ms), after which paste
/// interception is dead for the rest of the session with no error — so the callback only
/// reads an in-memory flag and posts a message. Every slow step (dialog, process inspection,
/// Authenticode, SQLite) happens after it returns.
/// </para>
/// </summary>
internal sealed class PasteInterceptor : IDisposable
{
    /// <summary>Private message used to leave the hook procedure before doing real work.</summary>
    private const int WM_PASTE_ATTEMPT = 0x0400 + 1;   // WM_APP + 1

    /// <summary>Pause after handing focus back, before the synthetic keystroke.</summary>
    // ponytail: fixed 80 ms settle, raise it if a slow app misses the replayed paste.
    private const int FocusSettleMs = 80;

    private readonly Func<bool> _shouldIntercept;
    private readonly Func<IntPtr, Task> _onPasteAttempt;
    private readonly AppNativeMethods.LowLevelKeyboardProc _hookProc;   // held so the GC cannot collect the callback
    private readonly IntPtr _hook;
    private readonly DispatchWindow _window;
    private bool _disposed;

    /// <param name="shouldIntercept">
    /// Fast, allocation-free predicate answering "is there a sensitive copy pending?".
    /// Runs inside the hook procedure, so it must not touch the disk, the clipboard, or the UI.
    /// </param>
    /// <param name="onPasteAttempt">
    /// Invoked on the message loop with the window that was about to receive the paste.
    /// </param>
    public PasteInterceptor(Func<bool> shouldIntercept, Func<IntPtr, Task> onPasteAttempt)
    {
        _shouldIntercept = shouldIntercept;
        _onPasteAttempt  = onPasteAttempt;
        _window          = new DispatchWindow(OnPasteAttemptPosted);
        _hookProc        = HookProc;

        _hook = AppNativeMethods.SetWindowsHookEx(
            AppNativeMethods.WH_KEYBOARD_LL, _hookProc, AppNativeMethods.GetModuleHandle(null), 0);

        if (_hook == IntPtr.Zero)
            throw new InvalidOperationException(
                $"SetWindowsHookEx failed ({Marshal.GetLastWin32Error()}) — paste interception unavailable.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hook procedure — must stay trivial
    // ─────────────────────────────────────────────────────────────────────────

    private IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && IsPasteKeystroke(wParam, lParam) && _shouldIntercept())
        {
            // Swallow the keystroke and continue on the message loop.
            IntPtr target = AppNativeMethods.GetForegroundWindow();
            AppNativeMethods.PostMessage(_window.Handle, WM_PASTE_ATTEMPT, target, IntPtr.Zero);
            return 1;
        }

        return AppNativeMethods.CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
    }

    private static bool IsPasteKeystroke(IntPtr wParam, IntPtr lParam)
    {
        int message = (int)wParam;
        if (message != AppNativeMethods.WM_KEYDOWN && message != AppNativeMethods.WM_SYSKEYDOWN)
            return false;

        var key = Marshal.PtrToStructure<AppNativeMethods.KBDLLHOOKSTRUCT>(lParam);

        // Our own replayed paste — let it through, or we would loop.
        if ((key.flags & AppNativeMethods.LLKHF_INJECTED) != 0) return false;

        bool ctrl  = IsDown(AppNativeMethods.VK_CONTROL);
        bool shift = IsDown(AppNativeMethods.VK_SHIFT);

        return (ctrl  && key.vkCode == AppNativeMethods.VK_V)
            || (shift && key.vkCode == AppNativeMethods.VK_INSERT);
    }

    private static bool IsDown(int virtualKey) =>
        (AppNativeMethods.GetAsyncKeyState(virtualKey) & 0x8000) != 0;

    // ─────────────────────────────────────────────────────────────────────────
    // Message-loop continuation
    // ─────────────────────────────────────────────────────────────────────────

    private async void OnPasteAttemptPosted(IntPtr targetHwnd)
    {
        try
        {
            await _onPasteAttempt(targetHwnd);
        }
        catch (Exception ex)
        {
            // A failed prompt must never take the tray app down.
            Debug.WriteLine($"ClipboardGuard: paste handling failed — {ex}");
        }
    }

    /// <summary>
    /// Hands focus back to <paramref name="targetHwnd"/> and replays Ctrl+V into it.
    /// Legal because our own window is foreground while the prompt is up, and a process
    /// that owns the foreground window may hand it to another.
    /// </summary>
    public static async Task ReplayPasteAsync(IntPtr targetHwnd)
    {
        if (targetHwnd != IntPtr.Zero)
            AppNativeMethods.SetForegroundWindow(targetHwnd);

        await Task.Delay(FocusSettleMs);

        AppNativeMethods.keybd_event(AppNativeMethods.VK_CONTROL, 0, 0, UIntPtr.Zero);
        AppNativeMethods.keybd_event(AppNativeMethods.VK_V, 0, 0, UIntPtr.Zero);
        AppNativeMethods.keybd_event(AppNativeMethods.VK_V, 0, AppNativeMethods.KEYEVENTF_KEYUP, UIntPtr.Zero);
        AppNativeMethods.keybd_event(AppNativeMethods.VK_CONTROL, 0, AppNativeMethods.KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_hook != IntPtr.Zero) AppNativeMethods.UnhookWindowsHookEx(_hook);
        if (_window.Handle != IntPtr.Zero) _window.DestroyHandle();
    }

    /// <summary>Invisible window that receives <see cref="WM_PASTE_ATTEMPT"/> from the hook.</summary>
    private sealed class DispatchWindow : NativeWindow
    {
        private readonly Action<IntPtr> _onPasteAttempt;

        public DispatchWindow(Action<IntPtr> onPasteAttempt)
        {
            _onPasteAttempt = onPasteAttempt;
            CreateHandle(new CreateParams
            {
                Caption = "ClipboardGuardPasteDispatch",
                Parent  = AppNativeMethods.HWND_MESSAGE,
            });
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_PASTE_ATTEMPT)
            {
                _onPasteAttempt(m.WParam);
                return;
            }

            base.WndProc(ref m);
        }
    }
}
