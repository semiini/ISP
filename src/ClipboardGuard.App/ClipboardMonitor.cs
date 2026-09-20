using ClipboardGuard.App.Native;

namespace ClipboardGuard.App;

/// <summary>
/// Raises <see cref="ClipboardUpdated"/> when a copy occurs, via a message-only window
/// registered with <c>AddClipboardFormatListener</c> (<c>WM_CLIPBOARDUPDATE</c>).
/// <para>
/// The paste side of the pipeline is driven by <see cref="PasteInterceptor"/>, not by
/// foreground-window changes.
/// </para>
/// The event arrives on the thread that constructed the monitor — the UI thread — so
/// handlers may touch the clipboard and Windows Forms directly.
/// </summary>
internal sealed class ClipboardMonitor : IDisposable
{
    private readonly MessageWindow _window;
    private bool _disposed;

    /// <summary>Raised when the system clipboard content changes.</summary>
    public event EventHandler? ClipboardUpdated;

    public ClipboardMonitor()
    {
        _window = new MessageWindow(() => ClipboardUpdated?.Invoke(this, EventArgs.Empty));

        if (!AppNativeMethods.AddClipboardFormatListener(_window.Handle))
            throw new InvalidOperationException("AddClipboardFormatListener failed — clipboard monitoring unavailable.");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

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
