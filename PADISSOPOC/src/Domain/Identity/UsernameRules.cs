using System.Text.RegularExpressions;

namespace Padi.Services.Authentication.Domain.Identity;

/// <summary>
/// The constraint Cognito enforces on the <c>Username</c> request parameter of SignUp,
/// ForgotPassword, ConfirmSignUp and the admin operations: 1–128 characters matching
/// <c>[\p{L}\p{M}\p{S}\p{N}\p{P}]+</c>. Whitespace is absent from that set, so a name
/// containing a space is rejected outright.
///
/// This has to be checked by hand because Cognito does not apply it where the value is
/// actually written. <c>preferred_username</c> is set through an attribute update, and
/// attribute values are capped at 2048 characters with no pattern at all — so Cognito
/// accepts "john smith" as an alias and then refuses it everywhere the user would type it.
/// The pool cannot help either: schema constraints support only min and max length.
/// </summary>
public static partial class UsernameRules
{
    public const int MaxLength = 128;

    /// <summary>
    /// Mirrors the Cognito Username pattern exactly — do not widen.
    ///
    /// Note that .NET applies these categories per UTF-16 code unit, so an astral-plane
    /// character such as an emoji is seen as a surrogate pair and rejected, even though
    /// the same pattern accepts it in an engine that matches by code point. The browser
    /// validator rejects astral characters explicitly so the two agree.
    /// </summary>
    [GeneratedRegex(@"^[\p{L}\p{M}\p{S}\p{N}\p{P}]+$")]
    private static partial Regex Allowed();

    /// <summary>Returns null when valid, otherwise a message naming the problem.</summary>
    public static string? Validate(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return "Username is required.";
        }

        if (candidate != candidate.Trim())
        {
            return "Username cannot start or end with a space.";
        }

        if (candidate.Length > MaxLength)
        {
            return $"Username cannot be longer than {MaxLength} characters.";
        }

        if (candidate.Any(char.IsWhiteSpace))
        {
            return "Username cannot contain spaces.";
        }

        return Allowed().IsMatch(candidate)
            ? null
            : "Username contains a character Cognito does not accept.";
    }

    public static bool IsValid(string? candidate) => Validate(candidate) is null;
}
