using System.Globalization;

namespace Padi.Services.Authentication.Domain.Identity;

/// <summary>
/// Cognito's constraint on the <c>birthdate</c> standard attribute: "Value must be a valid
/// 10 character date in the format YYYY-MM-DD."
///
/// Shape alone is not enough — <c>2026-02-31</c> is ten characters and correctly formatted
/// but not a date. Parsing exactly catches that here rather than leaving Cognito to reject
/// it with a less specific message.
/// </summary>
public static class BirthdateRules
{
    public const string Format = "yyyy-MM-dd";

    /// <summary>Regex for the shape only, for annotation-level checks and the browser.</summary>
    public const string Pattern = @"^\d{4}-\d{2}-\d{2}$";

    /// <summary>Returns null when valid, otherwise a message naming the problem.</summary>
    public static string? Validate(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return "Date of birth is required.";
        }

        return DateOnly.TryParseExact(
            candidate, Format, CultureInfo.InvariantCulture, DateTimeStyles.None, out _)
            ? null
            : "Date of birth must be a real date in YYYY-MM-DD form.";
    }

    public static bool IsValid(string? candidate) => Validate(candidate) is null;
}
