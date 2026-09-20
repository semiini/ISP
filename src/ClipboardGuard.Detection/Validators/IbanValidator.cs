using System.Numerics;
using System.Text;

namespace ClipboardGuard.Detection.Validators;

/// <summary>
/// Validates International Bank Account Numbers (IBAN) using the ISO 7064 MOD 97-10 checksum algorithm.
/// </summary>
public static class IbanValidator
{
    /// <summary>
    /// Checks if a string formatted as an IBAN is valid according to ISO 13616 / ISO 7064.
    /// Spaces and hyphens are ignored.
    /// </summary>
    public static bool IsValid(string iban)
    {
        if (string.IsNullOrWhiteSpace(iban))
            return false;

        // Strip spaces and hyphens
        var clean = new StringBuilder();
        foreach (char c in iban)
        {
            if (!char.IsWhiteSpace(c) && c != '-')
                clean.Append(char.ToUpperInvariant(c));
        }

        string normalized = clean.ToString();
        // IBAN length is between 15 and 34 characters
        if (normalized.Length is < 15 or > 34)
            return false;

        // First 2 characters must be letters (country code)
        if (!char.IsLetter(normalized[0]) || !char.IsLetter(normalized[1]))
            return false;

        // Next 2 characters must be digits (check digits)
        if (!char.IsDigit(normalized[2]) || !char.IsDigit(normalized[3]))
            return false;

        // Rearrange: move the first 4 characters to the end
        string rearranged = normalized[4..] + normalized[..4];

        // Replace each letter with two digits (A=10, B=11, ..., Z=35)
        var numericIban = new StringBuilder();
        foreach (char c in rearranged)
        {
            if (char.IsDigit(c))
            {
                numericIban.Append(c);
            }
            else if (char.IsLetter(c))
            {
                numericIban.Append((c - 'A' + 10).ToString());
            }
            else
            {
                return false;
            }
        }

        // Calculate MOD 97 using BigInteger or chunked division
        if (BigInteger.TryParse(numericIban.ToString(), out var bigNumber))
        {
            return bigNumber % 97 == 1;
        }

        return false;
    }
}
