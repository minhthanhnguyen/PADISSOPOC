namespace Padi.Services.Authentication.Application.Abstractions;

/// <summary>
/// The outcome of a password sign-in: either tokens, or a challenge Cognito wants answered
/// first. Exactly one of the two is set.
/// </summary>
public sealed record SignInOutcome(IssuedTokens? Tokens, string? Challenge)
{
    public static SignInOutcome Succeeded(IssuedTokens tokens) => new(tokens, null);

    public static SignInOutcome Challenged(string challenge) => new(null, challenge);
}

/// <summary>
/// Signs a user in with a username and password.
///
/// Every sign-in — password, one-time code, passkey — runs on a server-side app client that
/// has a secret, using the Admin* operations under the service's IAM role. No client a
/// browser can use offers any sign-in flow, so a caller cannot reproduce these against
/// Cognito directly: sign-in happens only through this API, where it is throttled and can be
/// put behind WAF.
/// </summary>
public interface IPasswordAuthenticator
{
    Task<SignInOutcome> SignInAsync(
        string username, string password, CancellationToken ct = default);
}

/// <summary>Passwordless first factors, as offered by Cognito's choice-based sign-in.</summary>
public enum PasswordlessFactor
{
    EmailOtp,
    SmsOtp,
    Passkey,
}

/// <summary>
/// A challenge Cognito has issued and the user must answer.
/// </summary>
/// <param name="Session">Opaque; must be sent back unchanged with the answer.</param>
/// <param name="CodeDestination">Masked address or number a one-time code went to. Null for passkeys.</param>
/// <param name="CredentialRequestOptions">
/// For passkeys: the WebAuthn <c>PublicKeyCredentialRequestOptions</c> as JSON, for the
/// browser to pass to <c>navigator.credentials.get</c>. Null for one-time codes.
/// </param>
public sealed record SignInChallenge(
    PasswordlessFactor Factor,
    string Session,
    string? CodeDestination,
    string? CredentialRequestOptions);

/// <summary>
/// Passwordless sign-in in two steps: start a challenge for the chosen factor, then answer it
/// with the emailed or texted code, or the passkey assertion. The browser never talks to
/// Cognito's sign-in operations itself — it only runs the WebAuthn ceremony locally.
/// </summary>
public interface IPasswordlessSignIn
{
    Task<SignInChallenge> StartAsync(string username, PasswordlessFactor factor, CancellationToken ct = default);

    /// <summary>
    /// <paramref name="answer"/> is the code for one-time codes, or the WebAuthn
    /// <c>AuthenticationResponseJSON</c> for passkeys.
    /// </summary>
    Task<SignInOutcome> AnswerAsync(
        string username, PasswordlessFactor factor, string session, string answer, CancellationToken ct = default);
}

/// <summary>
/// Refreshing and revoking the tokens sign-in issued. Both need the server-side client's
/// secret, which is why the browser cannot do either itself.
/// </summary>
public interface ISessionTokens
{
    /// <summary>
    /// New ID and access tokens. <paramref name="username"/> is the <c>username</c> claim of
    /// the current tokens — Cognito keys the secret hash for a refresh on it, not on an alias.
    /// </summary>
    Task<IssuedTokens> RefreshAsync(string username, string refreshToken, CancellationToken ct = default);

    /// <summary>Revokes the refresh token and the access tokens issued from it.</summary>
    Task RevokeAsync(string refreshToken, CancellationToken ct = default);
}

/// <summary>
/// The requested passwordless factor is not available for this account — no passkey
/// registered, no phone number, and so on. <see cref="Available"/> lists what Cognito offered.
/// </summary>
public sealed class FactorUnavailableException(IReadOnlyList<string> available)
    : Exception("That sign-in method is not available for this account.")
{
    public IReadOnlyList<string> Available { get; } = available;
}

/// <summary>
/// A challenge answer or token refresh was rejected: a wrong or expired code, a passkey
/// Cognito would not accept, an expired sign-in session, or a revoked refresh token.
/// </summary>
public sealed class ChallengeFailedException(string message) : Exception(message);

/// <summary>
/// Self-service password reset for a user who cannot sign in.
///
/// Both operations are Cognito's client-id-only flows, so they need no IAM and an
/// anonymous caller can do nothing here they could not do against Cognito directly.
/// </summary>
public interface IPasswordReset
{
    /// <summary>
    /// Starts a reset and returns the masked destination the code went to.
    ///
    /// Must not distinguish a known user from an unknown one. The pool's
    /// PreventUserExistenceErrors setting makes Cognito return a fabricated destination
    /// rather than an error, and that response is passed through unchanged.
    /// </summary>
    Task<string?> StartAsync(string username, CancellationToken ct = default);

    Task CompleteAsync(string username, string code, string newPassword, CancellationToken ct = default);
}

/// <summary>
/// Raised when credentials are rejected, or when the user does not exist.
///
/// Deliberately one exception for both: distinguishing them would turn sign-in into a
/// user-enumeration oracle, which is exactly what the pool's PreventUserExistenceErrors
/// setting avoids on the client-side flows.
/// </summary>
public sealed class AuthenticationFailedException()
    : Exception("Incorrect username or password.");

/// <summary>
/// Raised when the credentials were right but the account has never been confirmed.
///
/// Reported separately from a plain failure so the client can send the user back to
/// confirmation. It only reveals the account's state to someone who already proved they
/// know the password, so it is not an enumeration channel.
/// </summary>
public sealed class AccountNotConfirmedException()
    : Exception("This account has not been confirmed yet.");

/// <summary>Raised when Cognito's own attempt limit is hit — surfaced as 429, not 400.</summary>
public sealed class TooManyAttemptsException()
    : Exception("Too many attempts. Wait a few minutes and try again.");
