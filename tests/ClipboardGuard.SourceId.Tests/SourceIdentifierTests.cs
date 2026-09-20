namespace ClipboardGuard.SourceId.Tests;

/// <summary>
/// Placeholder test class — replace with real tests in Task 2.
/// </summary>
public class SourceIdentifierTests
{
    [Fact]
    public void Placeholder_ShouldPass()
    {
        // TODO: Implement tests when Task 2 (Source Identification Module) is complete.
        // Expected coverage:
        //  - Classifies known trusted process names → SourceCategory.Trusted
        //  - Classifies browser processes            → SourceCategory.Business
        //  - Classifies IDE processes                → SourceCategory.Development
        //  - Classifies password-manager processes   → SourceCategory.Credential
        //  - Unknown processes                       → SourceCategory.Unknown
        Assert.True(true);
    }
}
