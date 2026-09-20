namespace ClipboardGuard.Detection.Validators;

/// <summary>
/// Validates payment card numbers using the Luhn checksum algorithm (mod 10).
/// </summary>
public static class LuhnValidator
{
    /// <summary>
    /// Checks if a string containing digits satisfies the Luhn algorithm.
    /// Non-digit characters (spaces, dashes) are ignored.
    /// </summary>
    public static bool IsValid(string cardNumber)
    {
        if (string.IsNullOrWhiteSpace(cardNumber))
            return false;

        int sum = 0;
        bool alternate = false;
        int digitCount = 0;

        for (int i = cardNumber.Length - 1; i >= 0; i--)
        {
            char c = cardNumber[i];
            if (char.IsWhiteSpace(c) || c == '-')
                continue;

            if (!char.IsDigit(c))
                return false;

            int n = c - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9)
                    n -= 9;
            }

            sum += n;
            alternate = !alternate;
            digitCount++;
        }

        // Standard payment cards have 13 to 19 digits (Visa, Mastercard, Amex, etc.)
        return digitCount is >= 13 and <= 19 && sum % 10 == 0;
    }
}
