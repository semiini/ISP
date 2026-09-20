using System.Runtime.InteropServices;
using System.Text;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Masking.Native;

namespace ClipboardGuard.Masking;

/// <summary>
/// Data Masking & Clipboard Management Engine (Task 4).
/// Applies masking techniques to detected sensitive text spans and updates the Windows clipboard.
/// </summary>
public class MaskingEngine
{
    private readonly IReadOnlyDictionary<SensitiveDataType, MaskingRule> _rules;

    /// <summary>
    /// Initialises a new instance of <see cref="MaskingEngine"/> with optional custom rules.
    /// Falls back to <see cref="MaskingRule.Defaults"/>.
    /// </summary>
    public MaskingEngine(IReadOnlyDictionary<SensitiveDataType, MaskingRule>? customRules = null)
    {
        _rules = customRules ?? MaskingRule.Defaults;
    }

    /// <summary>
    /// Masks sensitive spans in <see cref="ClipboardContent.RawText"/> using the detection result.
    /// </summary>
    public string Mask(ClipboardContent content, DetectionResult detection, IReadOnlyDictionary<SensitiveDataType, MaskingRule>? ruleOverrides = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Mask(content.RawText, detection, ruleOverrides);
    }

    /// <summary>
    /// Masks all sensitive matches in <paramref name="rawText"/> based on the provided detection result.
    /// Processes matches in reverse index order so replacements do not distort earlier offsets.
    /// </summary>
    public string Mask(string rawText, DetectionResult detection, IReadOnlyDictionary<SensitiveDataType, MaskingRule>? ruleOverrides = null)
    {
        if (string.IsNullOrEmpty(rawText) || detection == null || !detection.HasSensitiveData)
        {
            return rawText ?? string.Empty;
        }

        var activeRules = ruleOverrides ?? _rules;

        // Sort matches in reverse order of StartIndex (from right to left)
        var sortedMatches = detection.Matches
            .OrderByDescending(m => m.StartIndex)
            .ToList();

        var sb = new StringBuilder(rawText);

        foreach (var match in sortedMatches)
        {
            int start = match.StartIndex;
            int length = match.Length;

            if (start < 0 || length <= 0 || start + length > sb.Length)
                continue;

            // Extract the original sensitive span
            string sensitiveValue = sb.ToString(start, length);

            // Resolve rule
            var rule = activeRules.TryGetValue(match.DataType, out var r)
                ? r
                : (MaskingRule.Defaults.TryGetValue(match.DataType, out var def)
                    ? def
                    : new MaskingRule { DataType = match.DataType, Technique = MaskingTechnique.Full });

            // Apply designated technique
            string maskedReplacement = MaskingTechniques.Apply(sensitiveValue, rule.Technique, match.DataType);

            // Replace span in StringBuilder
            sb.Remove(start, length);
            sb.Insert(start, maskedReplacement);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Writes the specified text to the Windows system clipboard using Win32 API.
    /// Retries multiple times in case the clipboard is temporarily locked by another process.
    /// </summary>
    /// <returns><see langword="true"/> if the clipboard was successfully updated; otherwise <see langword="false"/>.</returns>
    public virtual bool TrySetClipboardText(string text, int maxRetries = 5, int delayMs = 50)
    {
        ArgumentNullException.ThrowIfNull(text);

        for (int i = 0; i < maxRetries; i++)
        {
            if (ClipboardNativeMethods.OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    if (!ClipboardNativeMethods.EmptyClipboard())
                        return false;

                    byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
                    IntPtr hMem = ClipboardNativeMethods.GlobalAlloc(ClipboardNativeMethods.GMEM_MOVEABLE, (UIntPtr)bytes.Length);
                    if (hMem == IntPtr.Zero)
                        return false;

                    IntPtr pMem = ClipboardNativeMethods.GlobalLock(hMem);
                    if (pMem == IntPtr.Zero)
                    {
                        ClipboardNativeMethods.GlobalFree(hMem);
                        return false;
                    }

                    try
                    {
                        Marshal.Copy(bytes, 0, pMem, bytes.Length);
                    }
                    finally
                    {
                        ClipboardNativeMethods.GlobalUnlock(hMem);
                    }

                    IntPtr hResult = ClipboardNativeMethods.SetClipboardData(ClipboardNativeMethods.CF_UNICODETEXT, hMem);
                    return hResult != IntPtr.Zero;
                }
                finally
                {
                    ClipboardNativeMethods.CloseClipboard();
                }
            }

            Thread.Sleep(delayMs);
        }

        return false;
    }

    /// <summary>
    /// Convenience helper that masks content and updates the system clipboard.
    /// </summary>
    public string MaskAndSetClipboard(string rawText, DetectionResult detection, IReadOnlyDictionary<SensitiveDataType, MaskingRule>? ruleOverrides = null)
    {
        string masked = Mask(rawText, detection, ruleOverrides);
        TrySetClipboardText(masked);
        return masked;
    }
}
