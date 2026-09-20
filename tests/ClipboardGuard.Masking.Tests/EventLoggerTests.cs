using Xunit;
using ClipboardGuard.Core.Models;
using ClipboardGuard.Data;

namespace ClipboardGuard.Masking.Tests;

/// <summary>
/// Unit tests for <see cref="EventLogger"/> in ClipboardGuard.Data,
/// testing SQLite schema initialization, event logging, querying, and privacy constraints.
/// </summary>
public class EventLoggerTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly EventLogger _logger;

    public EventLoggerTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"cg_test_{Guid.NewGuid():N}.db");
        _logger = new EventLogger(_tempDbPath);
    }

    public void Dispose()
    {
        _logger.Dispose();
        if (File.Exists(_tempDbPath))
        {
            try { File.Delete(_tempDbPath); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task LogAsync_PersistsEvent_AndRetrievesById()
    {
        var evt = new ClipboardEvent
        {
            Source = new SourceInfo
            {
                ProcessName = "winword",
                Pid = 1234,
                WindowTitle = "Confidential Report.docx",
                ExecutablePath = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                Publisher = "Microsoft Corporation",
                Category = SourceCategory.Business,
                RiskLevel = RiskLevel.Medium
            },
            Destination = new DestinationInfo
            {
                ProcessName = "chrome",
                Pid = 5678,
                WindowTitle = "Chat - Google Chrome",
                ExecutablePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                Publisher = "Google LLC",
                Category = DestinationCategory.External,
                RiskLevel = RiskLevel.High
            },
            Detection = new DetectionResult
            {
                Matches =
                [
                    new SensitiveMatch
                    {
                        DataType = SensitiveDataType.CreditCardNumber,
                        StartIndex = 15,
                        Length = 16,
                        RiskLevel = RiskLevel.High
                    }
                ]
            },
            MaskedText = "Card number is ************1234 on record.",
            Decision = PolicyDecision.Mask,
            UserConfirmed = true,
            CopyTimestampUtc = DateTime.UtcNow.AddSeconds(-2),
            DecisionTimestampUtc = DateTime.UtcNow
        };

        await _logger.LogAsync(evt);

        var retrieved = await _logger.GetByIdAsync(evt.Id);

        Assert.NotNull(retrieved);
        Assert.Equal(evt.Id, retrieved.Id);
        Assert.Equal("winword", retrieved.Source.ProcessName);
        Assert.Equal(1234, retrieved.Source.Pid);
        Assert.Equal("Confidential Report.docx", retrieved.Source.WindowTitle);
        Assert.Equal(SourceCategory.Business, retrieved.Source.Category);
        Assert.Equal(RiskLevel.Medium, retrieved.Source.RiskLevel);

        Assert.NotNull(retrieved.Destination);
        Assert.Equal("chrome", retrieved.Destination.ProcessName);
        Assert.Equal(5678, retrieved.Destination.Pid);
        Assert.Equal(DestinationCategory.External, retrieved.Destination.Category);
        Assert.Equal(RiskLevel.High, retrieved.Destination.RiskLevel);

        Assert.True(retrieved.Detection.HasSensitiveData);
        var match = Assert.Single(retrieved.Detection.Matches);
        Assert.Equal(SensitiveDataType.CreditCardNumber, match.DataType);
        Assert.Equal(15, match.StartIndex);
        Assert.Equal(16, match.Length);

        Assert.Equal("Card number is ************1234 on record.", retrieved.MaskedText);
        Assert.Equal(PolicyDecision.Mask, retrieved.Decision);
        Assert.True(retrieved.UserConfirmed);
    }

    [Fact]
    public async Task QueryAsync_RetrievesEventsOrderedByTimestampDescending()
    {
        for (int i = 1; i <= 5; i++)
        {
            var evt = new ClipboardEvent
            {
                Source = new SourceInfo
                {
                    ProcessName = $"app{i}",
                    Pid = 1000 + i,
                    Category = SourceCategory.Business,
                    RiskLevel = RiskLevel.Low
                },
                MaskedText = $"Masked event {i}",
                Decision = PolicyDecision.Allow,
                CopyTimestampUtc = DateTime.UtcNow.AddMinutes(i)
            };

            await _logger.LogAsync(evt);
        }

        var results = await _logger.QueryAsync(limit: 3);

        Assert.Equal(3, results.Count);
        // Newest first
        Assert.Equal("app5", results[0].Source.ProcessName);
        Assert.Equal("app4", results[1].Source.ProcessName);
        Assert.Equal("app3", results[2].Source.ProcessName);
    }

    [Fact]
    public async Task GetTotalEventCountAsync_ReflectsLoggedEvents()
    {
        int initialCount = await _logger.GetTotalEventCountAsync();
        Assert.Equal(0, initialCount);

        var evt = new ClipboardEvent
        {
            Source = new SourceInfo { ProcessName = "notepad", Pid = 999 },
            MaskedText = "Test content",
            Decision = PolicyDecision.Allow
        };

        await _logger.LogAsync(evt);

        int newCount = await _logger.GetTotalEventCountAsync();
        Assert.Equal(1, newCount);
    }
}
