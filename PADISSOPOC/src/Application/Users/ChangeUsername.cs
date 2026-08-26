using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.Identity;

namespace Padi.Services.Authentication.Application.Users;

/// <summary>
/// Changes the caller's <c>preferred_username</c> — the mutable alias they sign in with.
///
/// The validation is the whole point of routing this through a use case. Cognito stores
/// <c>preferred_username</c> as a plain attribute, capped at 2048 characters with no pattern,
/// but only accepts 1–128 characters with no whitespace wherever the value is *used* as a
/// username. Writing an unchecked value produces an alias the user can never sign in with.
/// </summary>
public sealed class ChangeUsername(IUserSelfService users)
{
    public const string PreferredUsernameAttribute = "preferred_username";

    public async Task ExecuteAsync(string accessToken, string requested, CancellationToken ct = default)
    {
        var candidate = (requested ?? "").Trim();

        var problem = UsernameRules.Validate(candidate);
        if (problem is not null)
        {
            throw new DirectoryValidationException(problem);
        }

        await users.UpdateAttributesAsync(
            accessToken,
            new Dictionary<string, string> { [PreferredUsernameAttribute] = candidate },
            ct);
    }
}

/// <summary>
/// Sets a user's <c>preferred_username</c> from the management API.
///
/// Same rule as <see cref="ChangeUsername"/>, applied on the privileged path. Duplicated
/// deliberately rather than shared: an administrator acting on another account is a different
/// authorization decision, and collapsing the two would make it easy to reach the admin path
/// from a self-service caller.
/// </summary>
public sealed class SetUserUsername(IUserAdministration admin)
{
    public async Task ExecuteAsync(string userPoolId, string username, string requested, CancellationToken ct = default)
    {
        var candidate = (requested ?? "").Trim();

        var problem = UsernameRules.Validate(candidate);
        if (problem is not null)
        {
            throw new DirectoryValidationException(problem);
        }

        await admin.SetAttributesAsync(
            userPoolId,
            username,
            new Dictionary<string, string> { [ChangeUsername.PreferredUsernameAttribute] = candidate },
            ct);
    }
}
