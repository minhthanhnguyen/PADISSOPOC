using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api.Contracts;

/// <summary>
/// The caller's own profile. A projection, not a dump of the attribute map — a user should
/// not learn which internal attributes exist from their own profile response.
/// </summary>
public sealed record ProfileResponse(
    string? Sub,
    string? Username,
    string? Email,
    bool EmailVerified,
    string? GivenName,
    string? MiddleInitial,
    string? FamilyName,
    string? Birthdate,
    string? LastLogin,
    string? PadiId)
{
    public static ProfileResponse From(IReadOnlyDictionary<string, string> attributes)
    {
        string? Attr(string name) => attributes.TryGetValue(name, out var v) ? v : null;

        return new ProfileResponse(
            Sub: Attr("sub"),
            Username: Attr("preferred_username"),
            Email: Attr("email"),
            EmailVerified: Attr("email_verified") == "true",
            GivenName: Attr("given_name"),
            MiddleInitial: Attr("middle_name"),
            FamilyName: Attr("family_name"),
            Birthdate: Attr("birthdate"),
            LastLogin: Attr("custom:last_login"),
            PadiId: Attr("custom:padi_id"));
    }
}

/// <summary>
/// A user as the management API presents them. <c>AccountId</c> is the immutable Cognito
/// username — the opaque id — while <c>Username</c> is the mutable alias the user signs in
/// with. Naming them apart matters: callers that key on the wrong one break on a rename.
/// </summary>
public sealed record UserResponse(
    string AccountId,
    string? Username,
    string? Email,
    string Status,
    bool Enabled,
    DateTimeOffset? CreatedAt)
{
    public static UserResponse From(UserSummary user) => new(
        AccountId: user.Username,
        Username: user.PreferredUsername,
        Email: user.Email,
        Status: user.Status,
        Enabled: user.Enabled,
        CreatedAt: user.CreatedAt);
}

public sealed record UserPageResponse(IReadOnlyList<UserResponse> Users, string? NextToken);

public sealed record GroupsResponse(IReadOnlyList<string> Groups);

/// <summary>202 body for an email change: the masked address Cognito sent the code to.</summary>
public sealed record EmailChangeStartedResponse(string? Destination);

public sealed record HealthResponse(string Status);

/// <summary>
/// The result of starting a registration.
///
/// <c>AccountId</c> must be kept by the client until confirmation completes. An unconfirmed
/// account has no <c>preferred_username</c> alias yet, so this opaque id is the only value
/// Cognito accepts for confirming or resending — the name the user chose will not work.
/// </summary>
public sealed record RegistrationStartedResponse(
    string AccountId,
    bool Confirmed,
    string? CodeDestination);

public sealed record CodeResentResponse(string? CodeDestination);

/// <summary>
/// Masked destination a reset code was sent to.
///
/// Returned whether or not the account exists — for an unknown username Cognito fabricates
/// a plausible destination, and that is passed through so the response cannot be used to
/// probe which accounts are real.
/// </summary>
public sealed record PasswordResetStartedResponse(string? CodeDestination);

/// <summary>
/// Tokens from a successful sign-in.
///
/// The refresh token is returned to the browser, matching what Amplify already does with
/// tokens it obtains itself. A hardened deployment would hold it in an HttpOnly cookie so
/// script cannot read it — see the known gaps.
/// </summary>
public sealed record LoginResponse(
    string? IdToken,
    string? AccessToken,
    string? RefreshToken,
    int ExpiresIn,
    string? TokenType);
