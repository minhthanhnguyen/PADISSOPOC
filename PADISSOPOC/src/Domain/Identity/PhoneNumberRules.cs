using System.Text.RegularExpressions;

namespace Padi.Services.Authentication.Domain.Identity;

/// <summary>
/// Cognito's phone_number format: E.164 — a plus sign, the country code, then the number,
/// digits only (<c>+12065550123</c>). Cognito rejects anything else, but only after the call
/// is made and with a terse message, so it is checked here first.
///
/// Common formatting — spaces, hyphens, dots, parentheses — is stripped rather than rejected,
/// so "+1 (206) 555-0123" is accepted as "+12065550123". A missing country code is not
/// guessed: the plus sign is required.
/// </summary>
public static partial class PhoneNumberRules
{
    /// <summary>E.164 allows at most 15 digits after the plus. Fewer than 7 is not a real number.</summary>
    [GeneratedRegex(@"^\+[1-9]\d{6,14}$")]
    private static partial Regex E164();

    [GeneratedRegex(@"[\s\-.()]")]
    private static partial Regex Formatting();

    /// <summary>
    /// Returns the E.164 form, or a message naming the problem. Blank input is not an error:
    /// the number is optional, and blank means "none".
    /// </summary>
    public static (string? Value, string? Problem) Normalize(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return (null, null);
        }

        var compact = Formatting().Replace(candidate.Trim(), "");
        return E164().IsMatch(compact)
            ? (compact, null)
            : (null, "Phone number must include the country code, e.g. +1 206 555 0123.");
    }
}
