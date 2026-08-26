using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

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
public sealed class IssuedForClient(string clientId) : IAuthorizationRequirement
{
    public string ClientId { get; } = clientId;
}

public sealed class IssuedForClientHandler : AuthorizationHandler<IssuedForClient>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, IssuedForClient requirement)
    {
        var clientId = context.User.FindFirst("client_id")?.Value
                       ?? context.User.FindFirst("aud")?.Value;

        if (string.Equals(clientId, requirement.ClientId, StringComparison.Ordinal))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
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
