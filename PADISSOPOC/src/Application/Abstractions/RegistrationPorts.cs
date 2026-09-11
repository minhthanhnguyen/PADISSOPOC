namespace Padi.Services.Authentication.Application.Abstractions;

/// <summary>An account to create. <paramref name="AccountId"/> is the opaque Cognito username.</summary>
public sealed record NewAccount(
    string AccountId,
    string ChosenUsername,
    string Password,
    string Email,
    string? GivenName,
    string? MiddleInitial,
    string? FamilyName,
    string? Birthdate);

/// <summary>
/// The result of starting a registration.
///
/// <paramref name="AccountId"/> must be returned to the caller: until the account is
/// confirmed it has no <c>preferred_username</c> alias, so this opaque id is the only value
/// Cognito will accept for confirmation or a code resend.
/// </summary>
public sealed record RegistrationStarted(string AccountId, bool Confirmed, string? CodeDestination);

/// <summary>
/// Self-service registration. These are Cognito's unauthenticated operations — they take an
/// app client id rather than IAM credentials, which is what makes them safe to expose
/// through public endpoints.
/// </summary>
public interface IUserRegistration
{
    Task<RegistrationStarted> SignUpAsync(NewAccount account, CancellationToken ct = default);

    Task ConfirmAsync(string accountId, string code, CancellationToken ct = default);

    /// <summary>Returns the masked destination the replacement code was sent to.</summary>
    Task<string?> ResendCodeAsync(string accountId, CancellationToken ct = default);

    /// <summary>
    /// Whether a name is free to become a <c>preferred_username</c>.
    ///
    /// Needed because the alias is only assigned at confirmation: without this check two
    /// people can register the same name, and the second is rejected at confirmation time
    /// with an account already created and no way to change the staged name.
    /// </summary>
    Task<bool> IsUsernameAvailableAsync(string userPoolId, string username, CancellationToken ct = default);
}

/// <summary>
/// Supplies opaque account identifiers. A port for the same reason <see cref="IClock"/> is
/// one: it is non-deterministic, and a test needs to pin it.
/// </summary>
public interface IIdentifierFactory
{
    string NewId();
}
