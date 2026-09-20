using ClipboardGuard.App.Native;

namespace ClipboardGuard.App;

/// <summary>
/// Raises the two events that drive the §4.4 pipeline:
/// <list type="bullet">
///   <item><see cref="ClipboardUpdated"/> — a copy occurred (<c>WM_CLIPBOARDUPDATE</c>,
///         delivered to a message-only window registered with
///         <c>AddClipboardFormatListener</c>).</item>
///   <item><see cref="ForegroundChanged"/> — focus moved to another application, which is
///         the paste trigger described in README Task 8 ("foreground-window change after
///         copy"). Installed with <c>WINEVENT_SKIPOWNPROCESS</c> so ClipboardGuard's own
///         tray menus and dialogs never fire it.</item>
/// </list>
/// Both events arrive on the thread that constructed the monitor — the UI thread — so
/// handlers may touch the clipboard and Windows Forms directly.
/// </summary>
internal sealed class ClipboardMonitor : IDisposable
{
    private readonly MessageWindow _window;
    private readonly AppNativeMethods.WinEventProc _winEventProc;  // held to prevent GC of the callback
    private readonly IntPtr _winEventHook;
    private bool _disposed;

    /// <summary>Raised when the system clipboard content changes.</summary>
    public event EventHandler? ClipboardUpdated;

    /// <summary>Raised with the new foreground window's process ID when focus changes.</summary>
    public event EventHandler<int>? ForegroundChanged;

    public ClipboardMonitor()
    {
        _window = new MessageWindow(() => ClipboardUpdated?.Invoke(this, EventArgs.Empty));

        if (!AppNativeMethods.AddClipboardFormatListener(_window.Handle))
            throw new InvalidOperationException("AddClipboardFormatListener failed — clipboard monitoring unavailable.");

        _winEventProc = OnWinEvent;
        _winEventHook = AppNativeMethods.SetWinEventHook(
            AppNativeMethods.EVENT_SYSTEM_FOREGROUND,
            AppNativeMethods.EVENT_SYSTEM_FOREGROUND,
            IntPtr.Zero,
            _winEventProc,
            idProcess: 0,
            idThread: 0,
            AppNativeMethods.WINEVENT_OUTOFCONTEXT | AppNativeMethods.WINEVENT_SKIPOWNPROCESS);
    }

    private void OnWinEvent(
        IntPtr hook, uint eventType, IntPtr hwnd,
        int idObject, int idChild, uint thread, uint time)
    {
        if (eventType != AppNativeMethods.EVENT_SYSTEM_FOREGROUND || hwnd == IntPtr.Zero)
            return;

        AppNativeMethods.GetWindowThreadProcessId(hwnd, out uint pid);
        if (pid != 0) ForegroundChanged?.Invoke(this, (int)pid);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_winEventHook != IntPtr.Zero)
            AppNativeMethods.UnhookWinEvent(_winEventHook);

        if (_window.Handle != IntPtr.Zero)
        {
            AppNativeMethods.RemoveClipboardFormatListener(_window.Handle);
            _window.DestroyHandle();
        }
    }

    /// <summary>
    /// Invisible message-only window that receives <c>WM_CLIPBOARDUPDATE</c>.
    /// </summary>
    private sealed class MessageWindow : NativeWindow
    {
        private readonly Action _onClipboardUpdate;

        public MessageWindow(Action onClipboardUpdate)
        {
            _onClipboardUpdate = onClipboardUpdate;
            CreateHandle(new CreateParams
            {
                Caption = "ClipboardGuardListener",
                Parent  = AppNativeMethods.HWND_MESSAGE,
            });
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == AppNativeMethods.WM_CLIPBOARDUPDATE)
                _onClipboardUpdate();

            base.WndProc(ref m);
        }
    }
}
