namespace Padi.Services.Authentication.Application.Abstractions;

/// <summary>A user as the management API presents them. Not a Cognito SDK type.</summary>
public sealed record UserSummary(
    string Username,
    string? PreferredUsername,
    string? Email,
    string Status,
    bool Enabled,
    DateTimeOffset? CreatedAt,
    IReadOnlyDictionary<string, string> Attributes);

/// <summary>One page of users. <paramref name="NextToken"/> is null on the final page.</summary>
public sealed record UserPage(IReadOnlyList<UserSummary> Users, string? NextToken);

/// <summary>
/// Privileged operations performed with the service's own credentials, on any user.
///
/// Separate from <see cref="IUserSelfService"/> because the authority differs, not just the
/// operations: everything here acts on behalf of an administrator and must never be reachable
/// by a caller acting only on their own behalf.
/// </summary>
public interface IUserAdministration
{
    Task<UserPage> ListAsync(
        string userPoolId, string? filter, int limit, string? nextToken, CancellationToken ct = default);

    /// <summary>Returns null when no such user exists.</summary>
    Task<UserSummary?> GetAsync(string userPoolId, string username, CancellationToken ct = default);

    Task SetAttributesAsync(
        string userPoolId, string username, IReadOnlyDictionary<string, string> attributes, CancellationToken ct = default);

    Task SetEnabledAsync(string userPoolId, string username, bool enabled, CancellationToken ct = default);

    /// <summary>Forces a password reset on next sign-in and sends the user a reset code.</summary>
    Task ResetPasswordAsync(string userPoolId, string username, CancellationToken ct = default);

    Task<IReadOnlyList<string>> GetGroupsAsync(string userPoolId, string username, CancellationToken ct = default);

    Task AddToGroupAsync(string userPoolId, string username, string group, CancellationToken ct = default);

    Task RemoveFromGroupAsync(string userPoolId, string username, string group, CancellationToken ct = default);
}

/// <summary>
/// Operations a signed-in user performs on their own account, carried out with **their**
/// access token rather than the service's credentials.
///
/// Using the caller's token is deliberate: Cognito then applies the app client's attribute
/// write permissions, so a defect here cannot grant a user more than the client allows. The
/// admin path bypasses those permissions entirely, which is exactly why the two are separate.
/// </summary>
public interface IUserSelfService
{
    Task<IReadOnlyDictionary<string, string>> GetAsync(string accessToken, CancellationToken ct = default);

    Task UpdateAttributesAsync(
        string accessToken, IReadOnlyDictionary<string, string> attributes, CancellationToken ct = default);

    /// <summary>Starts an email change. Returns the masked destination Cognito sent the code to.</summary>
    Task<string?> StartEmailChangeAsync(string accessToken, string newEmail, CancellationToken ct = default);

    Task ConfirmEmailChangeAsync(string accessToken, string code, CancellationToken ct = default);
}

/// <summary>Raised when a caller asks for something the directory rejects as invalid input.</summary>
public sealed class DirectoryValidationException(string message) : Exception(message);

/// <summary>Raised when the requested user does not exist.</summary>
public sealed class UserNotFoundInDirectoryException(string username)
    : Exception($"No user '{username}' in this pool.");

/// <summary>Raised when a username or other alias is already taken.</summary>
public sealed class AliasAlreadyTakenException(string alias)
    : Exception($"'{alias}' is already in use.");
