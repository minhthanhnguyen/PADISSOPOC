using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.Identity;

namespace Padi.Services.Authentication.Application.Users;

public sealed record ResendRegistrationCodeCommand(string UserPoolId, string Username);

/// <summary>
/// Resends a sign-up code to the account registered under a chosen name, for a caller who
/// does not hold the opaque account id — typically someone returning on a different browser
/// from the one that signed up.
///
/// The answer must not reveal whether a pending sign-up exists under the name. When none is
/// found, the name itself is passed to ResendConfirmationCode, so the not-found case is
/// answered by Cognito's own existence protection — a simulated, plausible destination —
/// rather than by anything fabricated here. Both paths make the same two calls.
///
/// If the name is a confirmed account's alias, Cognito resolves it and reports the account
/// as already confirmed. That discloses nothing sign-up does not: it refuses a taken name.
/// </summary>
public sealed class ResendRegistrationCode(IUserRegistration registration)
{
    public async Task<string?> ExecuteAsync(
        ResendRegistrationCodeCommand command, CancellationToken ct = default)
    {
        var username = (command.Username ?? "").Trim();

        // A malformed name could never have been registered, so rejecting it up front
        // discloses nothing and saves both calls to AWS.
        if (UsernameRules.Validate(username) is { } problem)
        {
            throw new DirectoryValidationException(problem);
        }

        var accountId = await registration.FindPendingAccountIdAsync(command.UserPoolId, username, ct);
        return await registration.ResendCodeAsync(accountId ?? username, ct);
    }
}
