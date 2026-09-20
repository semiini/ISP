namespace ClipboardGuard.Destination.Tests;

/// <summary>
/// Placeholder test class — replace with real tests in Task 6.
/// </summary>
public class DestinationEngineTests
{
    [Fact]
    public void Placeholder_ShouldPass()
    {
        // TODO: Implement tests when Task 6 (Destination Analysis Engine) is complete.
        // Expected coverage:
        //  - Classifies internal tool process         → DestinationCategory.Trusted
        //  - Classifies local editor (notepad, etc.)  → DestinationCategory.Local
        //  - Classifies browser on public URL         → DestinationCategory.External
        //  - Classifies ChatGPT / Copilot windows     → DestinationCategory.Ai
        //  - Unknown process                          → DestinationCategory.Unknown
        //  - PolicyDecision derivation from source + detection + destination
        Assert.True(true);
    }
}
