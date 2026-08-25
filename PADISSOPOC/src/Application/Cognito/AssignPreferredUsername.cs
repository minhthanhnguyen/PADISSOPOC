using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.Identity;

namespace Padi.Services.Authentication.Application.Cognito;

public sealed record AssignPreferredUsernameCommand(
    string UserPoolId,
    string Username,
    IReadOnlyDictionary<string, string> UserAttributes);

/// <summary>
/// Promotes the name chosen at sign-up into <c>preferred_username</c>, the alias the user
/// actually signs in with.
///
/// This exists because Cognito refuses <c>preferred_username</c> in a SignUp request when
/// it is configured as an alias — the value can only be set once the account is confirmed.
/// Sign-up therefore parks the chosen name in <c>custom:signup_username</c> and this
/// trigger moves it across, so the user never sees the opaque <c>username</c> that Cognito
/// requires and can never change.
///
/// Unlike the sign-in triggers, a failure here is *not* swallowed. An account whose alias
/// was never assigned can only be reached by its UUID, which the user does not have — that
/// is a broken account, and failing confirmation visibly is better than creating one.
/// </summary>
public sealed class AssignPreferredUsername(IUserDirectory directory, IAuditLog audit)
{
    public const string DesiredUsernameAttribute = "custom:signup_username";
    public const string PreferredUsernameAttribute = "preferred_username";

    public async Task ExecuteAsync(AssignPreferredUsernameCommand command, CancellationToken ct = default)
    {
        if (command.UserAttributes.TryGetValue(PreferredUsernameAttribute, out var existing)
            && !string.IsNullOrWhiteSpace(existing))
        {
            // Already assigned. Confirmation can be replayed, and a federated or
            // admin-created user may arrive with the alias already set.
            return;
        }

        if (!command.UserAttributes.TryGetValue(DesiredUsernameAttribute, out var desired)
            || string.IsNullOrWhiteSpace(desired))
        {
            // Nothing to promote — an admin-created or federated account. The user signs
            // in by another route, so this is not an error.
            audit.Warn(
                $"No {DesiredUsernameAttribute} on confirmation for '{command.Username}'; " +
                "no preferred_username assigned.");
            return;
        }

        var alias = desired.Trim();

        // The client validates before sign-up, so reaching this means the staged value
        // bypassed it. Writing it anyway would produce an alias Cognito accepts on the
        // attribute but rejects wherever the user types it — a silently unusable account.
        var problem = UsernameRules.Validate(alias);
        if (problem is not null)
        {
            throw new InvalidOperationException(
                $"Cannot assign preferred_username for '{command.Username}': {problem}");
        }

        await directory.SetAttributeAsync(
            command.UserPoolId, command.Username, PreferredUsernameAttribute, alias, ct);

        audit.Record("PreferredUsernameAssigned", new Dictionary<string, object?>
        {
            ["userPoolId"] = command.UserPoolId,
            ["userName"] = command.Username,
            ["preferredUsername"] = alias,
        });
    }
}
