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
/// Unlike the rest of the public surface, this cannot use a client-id-only Cognito
/// operation: the app client deliberately has USER_PASSWORD_AUTH disabled, so the flow runs
/// as ADMIN_USER_PASSWORD_AUTH under the service's IAM role. That is the point — an
/// unauthenticated caller cannot reproduce it against Cognito directly, so sign-in can only
/// happen through this API, where it is throttled and can be put behind WAF.
/// </summary>
public interface IPasswordAuthenticator
{
    Task<SignInOutcome> SignInAsync(
        string username, string password, CancellationToken ct = default);
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
