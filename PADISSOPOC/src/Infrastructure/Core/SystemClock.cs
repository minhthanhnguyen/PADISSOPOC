using System.Text.Json;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Core;

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>
/// Writes single-line JSON to stdout, which Lambda forwards to CloudWatch Logs where
/// Logs Insights can query the fields directly. Uses Console rather than ILambdaLogger
/// so the port has no per-invocation context to thread through the container.
/// </summary>
public sealed class ConsoleAuditLog : IAuditLog
{
    public void Record(string eventName, IReadOnlyDictionary<string, object?> fields)
    {
        var record = new Dictionary<string, object?>(fields) { ["event"] = eventName };
        Console.WriteLine(JsonSerializer.Serialize(record));
    }

    public void Warn(string message) => Console.WriteLine(
        JsonSerializer.Serialize(new { level = "WARN", message }));

    public void Error(string message) => Console.Error.WriteLine(
        JsonSerializer.Serialize(new { level = "ERROR", message }));
}
