using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// Admin* Cognito operations, performed with the service's IAM role. Cognito SDK exceptions
/// are translated into the Application's own exception types so nothing above this layer has
/// to reference the AWS SDK to handle a failure.
/// </summary>
public sealed class CognitoUserAdministration(IAmazonCognitoIdentityProvider cognito) : IUserAdministration
{
    public async Task<UserPage> ListAsync(
        string userPoolId, string? filter, int limit, string? nextToken, CancellationToken ct = default)
    {
        var request = new ListUsersRequest
        {
            UserPoolId = userPoolId,
            Limit = Math.Clamp(limit, 1, 60),
            PaginationToken = string.IsNullOrWhiteSpace(nextToken) ? null : nextToken,
        };

        // ListUsers takes a single "attribute ^= value" clause, not free text. Anything else
        // would be silently ignored, so an unusable filter is rejected rather than dropped.
        if (!string.IsNullOrWhiteSpace(filter))
        {
            request.Filter = filter;
        }

        try
        {
            var response = await cognito.ListUsersAsync(request, ct);
            return new UserPage(
                response.Users.Select(ToSummary).ToList(),
                response.PaginationToken);
        }
        catch (InvalidParameterException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
    }

    public async Task<UserSummary?> GetAsync(string userPoolId, string username, CancellationToken ct = default)
    {
        try
        {
            var user = await cognito.AdminGetUserAsync(
                new AdminGetUserRequest { UserPoolId = userPoolId, Username = username }, ct);

            var attributes = user.UserAttributes.ToDictionary(a => a.Name, a => a.Value);
            return new UserSummary(
                user.Username,
                Attr(attributes, "preferred_username"),
                Attr(attributes, "email"),
                user.UserStatus?.Value ?? "UNKNOWN",
                user.Enabled ?? false,
                user.UserCreateDate,
                attributes);
        }
        catch (UserNotFoundException)
        {
            return null;
        }
    }

    public async Task SetAttributesAsync(
        string userPoolId, string username, IReadOnlyDictionary<string, string> attributes,
        CancellationToken ct = default)
    {
        try
        {
            await cognito.AdminUpdateUserAttributesAsync(new AdminUpdateUserAttributesRequest
            {
                UserPoolId = userPoolId,
                Username = username,
                UserAttributes = [.. attributes.Select(kv => new AttributeType { Name = kv.Key, Value = kv.Value })],
            }, ct);
        }
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(username);
        }
        catch (AliasExistsException)
        {
            throw new AliasAlreadyTakenException(
                attributes.TryGetValue("preferred_username", out var alias) ? alias : "value");
        }
        catch (InvalidParameterException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
    }

    public async Task SetEnabledAsync(
        string userPoolId, string username, bool enabled, CancellationToken ct = default)
    {
        try
        {
            if (enabled)
            {
                await cognito.AdminEnableUserAsync(
                    new AdminEnableUserRequest { UserPoolId = userPoolId, Username = username }, ct);
            }
            else
            {
                await cognito.AdminDisableUserAsync(
                    new AdminDisableUserRequest { UserPoolId = userPoolId, Username = username }, ct);
            }
        }
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(username);
        }
    }

    public async Task ResetPasswordAsync(string userPoolId, string username, CancellationToken ct = default)
    {
        try
        {
            await cognito.AdminResetUserPasswordAsync(
                new AdminResetUserPasswordRequest { UserPoolId = userPoolId, Username = username }, ct);
        }
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(username);
        }
    }

    public async Task<IReadOnlyList<string>> GetGroupsAsync(
        string userPoolId, string username, CancellationToken ct = default)
    {
        try
        {
            var response = await cognito.AdminListGroupsForUserAsync(
                new AdminListGroupsForUserRequest { UserPoolId = userPoolId, Username = username }, ct);

            return response.Groups.Select(g => g.GroupName).ToList();
        }
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(username);
        }
    }

    public async Task AddToGroupAsync(
        string userPoolId, string username, string group, CancellationToken ct = default)
    {
        try
        {
            await cognito.AdminAddUserToGroupAsync(new AdminAddUserToGroupRequest
            {
                UserPoolId = userPoolId,
                Username = username,
                GroupName = group,
            }, ct);
        }
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(username);
        }
        catch (ResourceNotFoundException)
        {
            throw new DirectoryValidationException($"No group '{group}' in this pool.");
        }
    }

    public async Task RemoveFromGroupAsync(
        string userPoolId, string username, string group, CancellationToken ct = default)
    {
        try
        {
            await cognito.AdminRemoveUserFromGroupAsync(new AdminRemoveUserFromGroupRequest
            {
                UserPoolId = userPoolId,
                Username = username,
                GroupName = group,
            }, ct);
        }
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(username);
        }
        catch (ResourceNotFoundException)
        {
            throw new DirectoryValidationException($"No group '{group}' in this pool.");
        }
    }

    private static UserSummary ToSummary(UserType user)
    {
        var attributes = user.Attributes.ToDictionary(a => a.Name, a => a.Value);
        return new UserSummary(
            user.Username,
            Attr(attributes, "preferred_username"),
            Attr(attributes, "email"),
            user.UserStatus?.Value ?? "UNKNOWN",
            user.Enabled ?? false,
            user.UserCreateDate,
            attributes);
    }

    private static string? Attr(IReadOnlyDictionary<string, string> attributes, string name) =>
        attributes.TryGetValue(name, out var value) ? value : null;
}
