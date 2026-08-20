using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

public sealed class CognitoUserDirectory(IAmazonCognitoIdentityProvider cognito) : IUserDirectory
{
    public async Task<DirectoryUser?> FindAsync(string userPoolId, string username, CancellationToken ct = default)
    {
        try
        {
            var user = await cognito.AdminGetUserAsync(
                new AdminGetUserRequest { UserPoolId = userPoolId, Username = username }, ct);

            var attributes = user.UserAttributes.ToDictionary(a => a.Name, a => a.Value);
            return new DirectoryUser(user.Username, attributes);
        }
        catch (UserNotFoundException)
        {
            // Surfaced as null rather than an exception; callers must not reveal the
            // difference between "no such user" and "no contact value".
            return null;
        }
    }

    public Task SetAttributeAsync(
        string userPoolId, string username, string name, string value, CancellationToken ct = default) =>
        cognito.AdminUpdateUserAttributesAsync(new AdminUpdateUserAttributesRequest
        {
            UserPoolId = userPoolId,
            Username = username,
            UserAttributes = [new AttributeType { Name = name, Value = value }],
        }, ct);
}
