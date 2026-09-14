using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.Identity;

namespace Padi.Services.Authentication.Application.Users;

public sealed record RegisterUserCommand(
    string UserPoolId,
    string Username,
    string Password,
    string Email,
    string? GivenName,
    string? MiddleInitial,
    string? FamilyName,
    string? Birthdate);

/// <summary>
/// Creates an unconfirmed account from a public, unauthenticated request.
///
/// The account's Cognito username is an opaque identifier generated here, never the name the
/// user typed — Cognito fixes the username at creation and it can never change, so the
/// user-facing name has to live in <c>preferred_username</c> instead. Cognito rejects
/// <c>preferred_username</c> in a SignUp request while it is an alias, so the chosen name is
/// staged in <c>custom:signup_username</c> and promoted by the PostConfirmation trigger.
/// </summary>
public sealed class RegisterUser(
    IUserRegistration registration,
    IIdentifierFactory identifiers,
    IAuditLog audit)
{
    public async Task<RegistrationStarted> ExecuteAsync(
        RegisterUserCommand command, CancellationToken ct = default)
    {
        var username = (command.Username ?? "").Trim();

        // All input is validated before any call to AWS. Ordering it the other way makes a
        // bad birthdate cost a round trip, and hides the validation failure behind whatever
        // the availability lookup happens to do.
        var problem = UsernameRules.Validate(username);
        if (problem is not null)
        {
            throw new DirectoryValidationException(problem);
        }

        // Optional attribute: an omitted birthdate is valid, a malformed one is not.
        var birthdate = string.IsNullOrWhiteSpace(command.Birthdate) ? null : command.Birthdate.Trim();
        if (birthdate is not null && BirthdateRules.Validate(birthdate) is { } dateProblem)
        {
            throw new DirectoryValidationException(dateProblem);
        }

        // Checked before the account exists. This is a deliberate disclosure — a sign-up
        // form has to say whether a name is taken — but it is confined to sign-up attempts
        // rather than exposed as a standalone lookup, so it costs an attacker a rate-limited
        // request per guess.
        if (!await registration.IsUsernameAvailableAsync(command.UserPoolId, username, ct))
        {
            throw new AliasAlreadyTakenException(username);
        }

        var account = new NewAccount(
            // Keyed by the chosen name so a pending sign-up can be found without the id —
            // see AccountIdentifier. The unique part still comes from the factory.
            AccountId: AccountIdentifier.Compose(username, identifiers.NewId()),
            ChosenUsername: username,
            Password: command.Password,
            Email: (command.Email ?? "").Trim(),
            GivenName: command.GivenName?.Trim(),
            MiddleInitial: command.MiddleInitial?.Trim(),
            FamilyName: command.FamilyName?.Trim(),
            Birthdate: birthdate);

        var result = await registration.SignUpAsync(account, ct);

        // The chosen name is recorded; the password and the account id are not.
        audit.Record("UserRegistered", new Dictionary<string, object?>
        {
            ["username"] = username,
            ["confirmed"] = result.Confirmed,
        });

        return result;
    }
}
