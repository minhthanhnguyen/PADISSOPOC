using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.Identity;

namespace Padi.Services.Authentication.Application.Cognito;

public sealed record SelfSignUpCheck(
    string UserPoolId,
    string Username,
    IReadOnlyDictionary<string, string> UserAttributes);

/// <summary>
/// A self sign-up refused by the PreSignUp trigger. <see cref="Code"/> is a stable token the
/// API recognises in Cognito's wrapped error; the rest is safe to show the person signing up.
/// </summary>
public sealed class SignUpRejectedException(string code, string message) : Exception($"{code}: {message}")
{
    public const string UsernameTaken = "username-taken";

    public string Code { get; } = code;
}

/// <summary>
/// Enforces the API's sign-up rules on every self sign-up, however it arrives.
///
/// Self sign-up is open at Cognito, and <c>SignUp</c> needs only the public app client id. The
/// API minting an opaque id, validating the chosen name and checking it is free were all
/// optional for anyone calling Cognito directly. Such a caller could pick any username,
/// stage a name that <c>PostConfirmation</c> would refuse — leaving a confirmed account with
/// no alias — or claim a name already in use. Running the same checks here makes them
/// unconditional. The API still checks first, so its callers get a clear 409 before any
/// account exists; this is the backstop.
///
/// Only <c>PreSignUp_SignUp</c> is checked. Admin-created and federated users are created by
/// trusted paths and follow their own rules.
/// </summary>
public sealed class CheckSelfSignUp(IUsernameAvailability availability, IAuditLog audit)
{
    public const string SelfSignUpTrigger = "PreSignUp_SignUp";

    public async Task ExecuteAsync(SelfSignUpCheck check, CancellationToken ct = default)
    {
        try
        {
            await CheckAsync(check, ct);
        }
        catch (SignUpRejectedException ex)
        {
            // Direct callers see only Cognito's error, so this is where a pattern of
            // attempts to go around the API becomes visible.
            audit.Record("SelfSignUpRejected", new Dictionary<string, object?>
            {
                ["userPoolId"] = check.UserPoolId,
                ["userName"] = check.Username,
                ["reason"] = ex.Code,
            });
            throw;
        }
    }

    private async Task CheckAsync(SelfSignUpCheck check, CancellationToken ct)
    {
        string? Attr(string name) =>
            check.UserAttributes.TryGetValue(name, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;

        var chosen = Attr(AssignPreferredUsername.DesiredUsernameAttribute)?.Trim();
        if (chosen is null)
        {
            throw new SignUpRejectedException("missing-username", "A username is required.");
        }

        // Without this, PostConfirmation refuses the name after the account is confirmed,
        // leaving it with no alias to sign in with.
        if (UsernameRules.Validate(chosen) is { } problem)
        {
            throw new SignUpRejectedException("invalid-username", problem);
        }

        // The API always produces exactly this shape. Anything else chose its own Cognito
        // username, which the rest of the design — resend by name, the opaque-id model —
        // assumes cannot happen.
        if (!AccountIdentifier.IsIdFor(check.Username, chosen))
        {
            throw new SignUpRejectedException("invalid-account-id", "Sign up through the PADI API.");
        }

        // The account cannot be confirmed without one: the code is emailed.
        if (Attr("email") is null)
        {
            throw new SignUpRejectedException("missing-email", "An email address is required.");
        }

        if (!await availability.IsUsernameAvailableAsync(check.UserPoolId, chosen, ct))
        {
            throw new SignUpRejectedException(SignUpRejectedException.UsernameTaken, "That username is already taken.");
        }
    }
}
