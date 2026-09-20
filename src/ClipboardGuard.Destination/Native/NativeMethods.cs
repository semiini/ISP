using System.Runtime.InteropServices;
using System.Text;

namespace ClipboardGuard.Destination.Native;

/// <summary>
/// P/Invoke declarations for the user32.dll functions used by the Destination
/// Analysis Engine (proposal §3.4, Fig. 4 step 1 — "detect foreground app on paste").
/// Internal — consumers use <see cref="ClipboardGuard.Destination.DestinationEngine"/> instead.
/// </summary>
internal static class NativeMethods
{
    /// <summary>Handle of the window the user is currently working with.</summary>
    [DllImport("user32.dll", SetLastError = false)]
    internal static extern IntPtr GetForegroundWindow();

    /// <summary>Resolves the process that owns a window.</summary>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    /// <summary>Copies a window's title-bar text into <paramref name="lpString"/>.</summary>
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    /// <summary>Length in characters of a window's title-bar text.</summary>
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern int GetWindowTextLength(IntPtr hWnd);
}
