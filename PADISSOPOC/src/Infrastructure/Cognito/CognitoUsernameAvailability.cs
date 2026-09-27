using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// Checks whether a name is already someone's <c>preferred_username</c>. Uses ListUsers, so
/// it needs IAM. Shared by the API's sign-up and the PreSignUp trigger.
/// </summary>
public sealed class CognitoUsernameAvailability(IAmazonCognitoIdentityProvider cognito) : IUsernameAvailability
{
    public async Task<bool> IsUsernameAvailableAsync(
        string userPoolId, string username, CancellationToken ct = default)
    {
        // preferred_username is one of the few filterable attributes. custom: attributes are
        // not, so a name staged on an unconfirmed account cannot be seen here — two people
        // can still race for the same name and the loser fails at confirmation.
        var response = await cognito.ListUsersAsync(new ListUsersRequest
        {
            UserPoolId = userPoolId,
            Filter = $"preferred_username = \"{username.Replace("\"", "\\\"")}\"",
            Limit = 1,
        }, ct);

        return response.Users.Count == 0;
    }
}
