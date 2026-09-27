using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api;

/// <summary>Pool settings resolved once at startup.</summary>
public sealed record PoolContext(string UserPoolId, string AdminGroup);

public static class Policies
{
    /// <summary>Any authenticated user, acting on their own account.</summary>
    public const string Caller = "caller";

    /// <summary>A member of the admin group, acting on any account.</summary>
    public const string Administrator = "administrator";
}

/// <summary>
/// Cognito access tokens put the app client in <c>client_id</c>, not <c>aud</c>, so the
/// standard audience check does not apply. Without this, a token minted by any other app
/// client on the same pool would be accepted.
/// </summary>
public sealed class IssuedForClient(IReadOnlyCollection<string> clientIds) : IAuthorizationRequirement
{
    public IReadOnlyCollection<string> ClientIds { get; } = clientIds;
}

public sealed class IssuedForClientHandler : AuthorizationHandler<IssuedForClient>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, IssuedForClient requirement)
    {
        var clientId = context.User.FindFirst("client_id")?.Value
                       ?? context.User.FindFirst("aud")?.Value;

        if (clientId is not null && requirement.ClientIds.Contains(clientId, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// The caller is an administrator <i>now</i> — not merely when their token was issued.
///
/// A token's <c>cognito:groups</c> claim is fixed for its lifetime (an hour). Checking only
/// the claim meant someone removed from the admin group, disabled, or signed out kept admin
/// rights until expiry — and could use that window to add themselves back to the group, so
/// the demotion never held.
/// </summary>
public sealed class CurrentAdministrator(string group) : IAuthorizationRequirement
{
    public string Group { get; } = group;
}

public sealed class CurrentAdministratorHandler(
    IUserSelfService sessions,
    IUserAdministration directory,
    PoolContext pool) : AuthorizationHandler<CurrentAdministrator>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, CurrentAdministrator requirement)
    {
        // The claim is a cheap pre-filter: non-admins are turned away without any calls to
        // Cognito, so ordinary tokens cannot be used to drive load onto it.
        if (!context.User.IsInCognitoGroup(requirement.Group) || context.Resource is not HttpContext http)
        {
            return;
        }

        // Access tokens carry the Cognito username as "username"; ID tokens do not, so an
        // ID token never passes this policy.
        var username = context.User.FindFirst("username")?.Value;
        if (string.IsNullOrEmpty(username))
        {
            return;
        }

        string token;
        try
        {
            token = http.AccessToken();
        }
        catch (DirectoryValidationException)
        {
            return;
        }

        // Two live checks, both required: the session is still honoured (not revoked, user
        // not disabled), and the user is in the group today.
        if (!await sessions.IsSessionActiveAsync(token, http.RequestAborted))
        {
            return;
        }

        IReadOnlyList<string> groups;
        try
        {
            groups = await directory.GetGroupsAsync(pool.UserPoolId, username, http.RequestAborted);
        }
        catch (UserNotFoundInDirectoryException)
        {
            return;
        }

        if (groups.Contains(requirement.Group, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
        }
    }
}

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Group membership arrives as repeated <c>cognito:groups</c> claims. Matched
    /// case-sensitively — Cognito group names are case-sensitive.
    /// </summary>
    public static bool IsInCognitoGroup(this ClaimsPrincipal user, string group) =>
        user.FindAll("cognito:groups").Any(c => string.Equals(c.Value, group, StringComparison.Ordinal));

    /// <summary>The immutable Cognito user id. Never the alias — that changes.</summary>
    public static string? Subject(this ClaimsPrincipal user) =>
        user.FindFirst("sub")?.Value;
}
