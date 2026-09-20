using System.Runtime.InteropServices;

namespace ClipboardGuard.SourceId.Native;

/// <summary>
/// P/Invoke declarations for the user32.dll and kernel32.dll functions
/// used by the Source Identification Module.
/// Internal — consumers use <see cref="ClipboardGuard.SourceId.SourceIdentifier"/> instead.
/// </summary>
internal static class NativeMethods
{
    // ─────────────────────────────────────────────────────────────────────────
    // user32.dll
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Retrieves the handle of the foreground window (the window the user is
    /// currently working with).
    /// </summary>
    [DllImport("user32.dll", SetLastError = false)]
    internal static extern IntPtr GetForegroundWindow();

    /// <summary>
    /// Retrieves the identifier of the thread that created the specified window
    /// and, optionally, the identifier of the process that created the window.
    /// </summary>
    /// <param name="hWnd">Handle to the window.</param>
    /// <param name="lpdwProcessId">
    /// Receives the process identifier. Pass <see langword="out"/> to obtain it.
    /// </param>
    /// <returns>The thread identifier.</returns>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    /// <summary>
    /// Copies the text of the specified window's title bar into a buffer.
    /// </summary>
    /// <param name="hWnd">Handle to the window.</param>
    /// <param name="lpString">Buffer that receives the title text.</param>
    /// <param name="nMaxCount">Maximum number of characters to copy.</param>
    /// <returns>Length in characters copied (excluding null terminator).</returns>
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);

    /// <summary>
    /// Retrieves the length of the specified window's title bar text.
    /// </summary>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern int GetWindowTextLength(IntPtr hWnd);
}
