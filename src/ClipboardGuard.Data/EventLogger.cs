using System.Data;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using ClipboardGuard.Core.Models;

namespace ClipboardGuard.Data;

/// <summary>
/// SQLite event logging module for <see cref="ClipboardEvent"/> (Task 5).
/// Persists pipeline events with source, destination, positional detection metadata,
/// and masked text. Never persists raw sensitive text.
/// </summary>
public class EventLogger : IDisposable, IAsyncDisposable
{
    private readonly string _connectionString;
    private bool _initialized;
    private readonly SemaphoreSlim _initLock = new(1, 1);

    /// <summary>
    /// Initialises a new instance of <see cref="EventLogger"/> with the specified database connection string or file path.
    /// Defaults to a persistent SQLite database under local AppData.
    /// </summary>
    public EventLogger(string? connectionStringOrPath = null)
    {
        if (string.IsNullOrWhiteSpace(connectionStringOrPath))
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string folder = Path.Combine(appData, "ClipboardGuard");
            Directory.CreateDirectory(folder);
            string dbPath = Path.Combine(folder, "clipboard_guard.db");
            _connectionString = $"Data Source={dbPath}";
        }
        else if (connectionStringOrPath.Contains('='))
        {
            _connectionString = connectionStringOrPath;
        }
        else
        {
            string? dir = Path.GetDirectoryName(connectionStringOrPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            _connectionString = $"Data Source={connectionStringOrPath}";
        }
    }

    /// <summary>
    /// Ensures the SQLite database schema is created and indexes are ready.
    /// </summary>
    public async Task EnsureInitializedAsync()
    {
        if (_initialized)
            return;

        await _initLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_initialized)
                return;

            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync().ConfigureAwait(false);

            const string schemaSql = """
                CREATE TABLE IF NOT EXISTS clipboard_events (
                    id TEXT PRIMARY KEY,
                    source_process TEXT NOT NULL,
                    source_pid INTEGER NOT NULL,
                    source_window_title TEXT,
                    source_executable_path TEXT,
                    source_publisher TEXT,
                    source_category TEXT NOT NULL,
                    source_risk_level TEXT NOT NULL,
                    destination_process TEXT,
                    destination_pid INTEGER,
                    destination_window_title TEXT,
                    destination_executable_path TEXT,
                    destination_publisher TEXT,
                    destination_category TEXT,
                    destination_risk_level TEXT,
                    detection_match_count INTEGER NOT NULL,
                    detection_max_risk_level TEXT NOT NULL,
                    detection_json TEXT NOT NULL,
                    masked_text TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    user_confirmed INTEGER,
                    copy_timestamp_utc TEXT NOT NULL,
                    decision_timestamp_utc TEXT NOT NULL,
                    paste_timestamp_utc TEXT,
                    processing_ms REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_copy_timestamp ON clipboard_events(copy_timestamp_utc);
                CREATE INDEX IF NOT EXISTS idx_events_decision ON clipboard_events(decision);
                """;

            await using var cmd = new SqliteCommand(schemaSql, connection);
            await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);

            _initialized = true;
        }
        finally
        {
            _initLock.Release();
        }
    }

    /// <summary>
    /// Persists a <see cref="ClipboardEvent"/> to the SQLite database.
    /// </summary>
    public async Task LogAsync(ClipboardEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        await EnsureInitializedAsync().ConfigureAwait(false);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        const string insertSql = """
            INSERT INTO clipboard_events (
                id,
                source_process, source_pid, source_window_title, source_executable_path, source_publisher, source_category, source_risk_level,
                destination_process, destination_pid, destination_window_title, destination_executable_path, destination_publisher, destination_category, destination_risk_level,
                detection_match_count, detection_max_risk_level, detection_json,
                masked_text, decision, user_confirmed,
                copy_timestamp_utc, decision_timestamp_utc, paste_timestamp_utc, processing_ms
            ) VALUES (
                @id,
                @source_process, @source_pid, @source_window_title, @source_executable_path, @source_publisher, @source_category, @source_risk_level,
                @destination_process, @destination_pid, @destination_window_title, @destination_executable_path, @destination_publisher, @destination_category, @destination_risk_level,
                @detection_match_count, @detection_max_risk_level, @detection_json,
                @masked_text, @decision, @user_confirmed,
                @copy_timestamp_utc, @decision_timestamp_utc, @paste_timestamp_utc, @processing_ms
            );
            """;

        await using var cmd = new SqliteCommand(insertSql, connection);

        cmd.Parameters.AddWithValue("@id", evt.Id.ToString("D"));
        cmd.Parameters.AddWithValue("@source_process", evt.Source.ProcessName);
        cmd.Parameters.AddWithValue("@source_pid", evt.Source.Pid);
        cmd.Parameters.AddWithValue("@source_window_title", (object?)evt.Source.WindowTitle ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@source_executable_path", (object?)evt.Source.ExecutablePath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@source_publisher", (object?)evt.Source.Publisher ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@source_category", evt.Source.Category.ToString());
        cmd.Parameters.AddWithValue("@source_risk_level", evt.Source.RiskLevel.ToString());

        if (evt.Destination != null)
        {
            cmd.Parameters.AddWithValue("@destination_process", evt.Destination.ProcessName);
            cmd.Parameters.AddWithValue("@destination_pid", evt.Destination.Pid);
            cmd.Parameters.AddWithValue("@destination_window_title", (object?)evt.Destination.WindowTitle ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_executable_path", (object?)evt.Destination.ExecutablePath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_publisher", (object?)evt.Destination.Publisher ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_category", evt.Destination.Category.ToString());
            cmd.Parameters.AddWithValue("@destination_risk_level", evt.Destination.RiskLevel.ToString());
        }
        else
        {
            cmd.Parameters.AddWithValue("@destination_process", DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_pid", DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_window_title", DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_executable_path", DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_publisher", DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_category", DBNull.Value);
            cmd.Parameters.AddWithValue("@destination_risk_level", DBNull.Value);
        }

        cmd.Parameters.AddWithValue("@detection_match_count", evt.Detection.Matches.Count);
        cmd.Parameters.AddWithValue("@detection_max_risk_level", evt.Detection.MaxRiskLevel.ToString());
        cmd.Parameters.AddWithValue("@detection_json", JsonConvert.SerializeObject(evt.Detection));

        cmd.Parameters.AddWithValue("@masked_text", evt.MaskedText);
        cmd.Parameters.AddWithValue("@decision", evt.Decision.ToString());
        cmd.Parameters.AddWithValue("@user_confirmed", evt.UserConfirmed.HasValue ? (evt.UserConfirmed.Value ? 1 : 0) : DBNull.Value);

        cmd.Parameters.AddWithValue("@copy_timestamp_utc", evt.CopyTimestampUtc.ToString("o"));
        cmd.Parameters.AddWithValue("@decision_timestamp_utc", evt.DecisionTimestampUtc.ToString("o"));
        cmd.Parameters.AddWithValue("@paste_timestamp_utc", evt.PasteTimestampUtc.HasValue ? evt.PasteTimestampUtc.Value.ToString("o") : DBNull.Value);
        cmd.Parameters.AddWithValue("@processing_ms", evt.ProcessingMs);

        await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Queries logged events within an optional time range, limited by <paramref name="limit"/>.
    /// Returns newest events first.
    /// </summary>
    public async Task<IReadOnlyList<ClipboardEvent>> QueryAsync(DateTime? fromUtc = null, DateTime? toUtc = null, int limit = 100)
    {
        await EnsureInitializedAsync().ConfigureAwait(false);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        string querySql = """
            SELECT
                id,
                source_process, source_pid, source_window_title, source_executable_path, source_publisher, source_category, source_risk_level,
                destination_process, destination_pid, destination_window_title, destination_executable_path, destination_publisher, destination_category, destination_risk_level,
                detection_json, masked_text, decision, user_confirmed,
                copy_timestamp_utc, decision_timestamp_utc, paste_timestamp_utc
            FROM clipboard_events
            WHERE (@fromUtc IS NULL OR copy_timestamp_utc >= @fromUtc)
              AND (@toUtc IS NULL OR copy_timestamp_utc <= @toUtc)
            ORDER BY copy_timestamp_utc DESC
            LIMIT @limit;
            """;

        await using var cmd = new SqliteCommand(querySql, connection);
        cmd.Parameters.AddWithValue("@fromUtc", fromUtc.HasValue ? fromUtc.Value.ToString("o") : DBNull.Value);
        cmd.Parameters.AddWithValue("@toUtc", toUtc.HasValue ? toUtc.Value.ToString("o") : DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", limit);

        var results = new List<ClipboardEvent>();
        await using var reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);

        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            results.Add(ReadEventFromRow(reader));
        }

        return results;
    }

    /// <summary>
    /// Retrieves a single event by its unique ID.
    /// </summary>
    public async Task<ClipboardEvent?> GetByIdAsync(Guid id)
    {
        await EnsureInitializedAsync().ConfigureAwait(false);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        const string querySql = """
            SELECT
                id,
                source_process, source_pid, source_window_title, source_executable_path, source_publisher, source_category, source_risk_level,
                destination_process, destination_pid, destination_window_title, destination_executable_path, destination_publisher, destination_category, destination_risk_level,
                detection_json, masked_text, decision, user_confirmed,
                copy_timestamp_utc, decision_timestamp_utc, paste_timestamp_utc
            FROM clipboard_events
            WHERE id = @id
            LIMIT 1;
            """;

        await using var cmd = new SqliteCommand(querySql, connection);
        cmd.Parameters.AddWithValue("@id", id.ToString("D"));

        await using var reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);
        if (await reader.ReadAsync().ConfigureAwait(false))
        {
            return ReadEventFromRow(reader);
        }

        return null;
    }

    /// <summary>
    /// Returns the total count of events in the log.
    /// </summary>
    public async Task<int> GetTotalEventCountAsync()
    {
        await EnsureInitializedAsync().ConfigureAwait(false);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        await using var cmd = new SqliteCommand("SELECT COUNT(*) FROM clipboard_events;", connection);
        var count = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
        return Convert.ToInt32(count);
    }

    private static ClipboardEvent ReadEventFromRow(SqliteDataReader reader)
    {
        var id = Guid.Parse(reader.GetString(0));

        var source = new SourceInfo
        {
            ProcessName = reader.GetString(1),
            Pid = reader.GetInt32(2),
            WindowTitle = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
            ExecutablePath = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
            Publisher = reader.IsDBNull(5) ? null : reader.GetString(5),
            Category = Enum.Parse<SourceCategory>(reader.GetString(6)),
            RiskLevel = Enum.Parse<RiskLevel>(reader.GetString(7))
        };

        DestinationInfo? destination = null;
        if (!reader.IsDBNull(8))
        {
            destination = new DestinationInfo
            {
                ProcessName = reader.GetString(8),
                Pid = reader.GetInt32(9),
                WindowTitle = reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
                ExecutablePath = reader.IsDBNull(11) ? string.Empty : reader.GetString(11),
                Publisher = reader.IsDBNull(12) ? null : reader.GetString(12),
                Category = Enum.Parse<DestinationCategory>(reader.GetString(13)),
                RiskLevel = Enum.Parse<RiskLevel>(reader.GetString(14))
            };
        }

        string detectionJson = reader.GetString(15);
        var detection = JsonConvert.DeserializeObject<DetectionResult>(detectionJson) ?? DetectionResult.Clean;

        string maskedText = reader.GetString(16);
        var decision = Enum.Parse<PolicyDecision>(reader.GetString(17));
        bool? userConfirmed = reader.IsDBNull(18) ? null : (reader.GetInt32(18) == 1);

        var copyTimestamp = DateTime.Parse(reader.GetString(19), null, System.Globalization.DateTimeStyles.RoundtripKind);
        var decisionTimestamp = DateTime.Parse(reader.GetString(20), null, System.Globalization.DateTimeStyles.RoundtripKind);
        DateTime? pasteTimestamp = reader.IsDBNull(21)
            ? null
            : DateTime.Parse(reader.GetString(21), null, System.Globalization.DateTimeStyles.RoundtripKind);

        return new ClipboardEvent
        {
            Id = id,
            Source = source,
            Destination = destination,
            Detection = detection,
            MaskedText = maskedText,
            Decision = decision,
            UserConfirmed = userConfirmed,
            CopyTimestampUtc = copyTimestamp,
            DecisionTimestampUtc = decisionTimestamp,
            PasteTimestampUtc = pasteTimestamp
        };
    }

    public void Dispose()
    {
        _initLock.Dispose();
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        _initLock.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }
}
