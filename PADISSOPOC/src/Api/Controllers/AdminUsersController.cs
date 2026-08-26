using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.Users;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Privileged operations on any account, restricted to members of the admin group.
///
/// These calls run under the service's IAM role and bypass the app client's attribute
/// permissions entirely, which is why every mutating action writes an audit record naming
/// the administrator *before* it acts. A call that fails partway still leaves evidence it
/// was attempted.
/// </summary>
[ApiController]
[Route("admin/users")]
[Authorize(Policy = Policies.Administrator)]
[Produces("application/json")]
public sealed class AdminUsersController(
    IUserAdministration users,
    SetUserUsername setUsername,
    PoolContext pool,
    IAuditLog audit) : ControllerBase
{
    /// <summary>
    /// Attributes this API will not write. <c>email_verified</c> is the dangerous one:
    /// setting it true would mark any address as verified and hand over account recovery
    /// without the holder ever proving control of the mailbox.
    /// </summary>
    private static readonly HashSet<string> Protected = new(StringComparer.Ordinal)
    {
        "sub", "email_verified", "phone_number_verified", "cognito:username", "identities",
    };

    [HttpGet]
    [ProducesResponseType(typeof(UserPageResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<UserPageResponse>> List(
        [FromQuery] ListUsersQuery query, CancellationToken ct)
    {
        var page = await users.ListAsync(pool.UserPoolId, query.Filter, query.Limit, query.NextToken, ct);
        return Ok(new UserPageResponse(
            page.Users.Select(UserResponse.From).ToList(),
            page.NextToken));
    }

    [HttpGet("{username}")]
    [ProducesResponseType(typeof(UserResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserResponse>> Get(string username, CancellationToken ct)
    {
        var user = await users.GetAsync(pool.UserPoolId, username, ct);
        return user is null
            ? Problem(title: $"No user '{username}'.", statusCode: StatusCodes.Status404NotFound)
            : Ok(UserResponse.From(user));
    }

    [HttpPatch("{username}/attributes")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> SetAttributes(
        string username, [FromBody] SetAttributesRequest request, CancellationToken ct)
    {
        var blocked = request.Attributes.Keys.Where(Protected.Contains).ToList();
        if (blocked.Count > 0)
        {
            return Problem(
                title: "Those attributes cannot be set here.",
                detail: string.Join(", ", blocked),
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Routed to its own action so it cannot skip UsernameRules.
        if (request.Attributes.ContainsKey("preferred_username"))
        {
            return Problem(
                title: "Use PUT /admin/users/{username}/username instead.",
                detail: "preferred_username is validated before it is written.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Audit("AdminSetAttributes", username, new() { ["keys"] = request.Attributes.Keys });
        await users.SetAttributesAsync(pool.UserPoolId, username, request.Attributes, ct);
        return NoContent();
    }

    [HttpPut("{username}/username")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> SetUsername(
        string username, [FromBody] SetUsernameRequest request, CancellationToken ct)
    {
        Audit("AdminSetUsername", username, new() { ["requested"] = request.Username });
        await setUsername.ExecuteAsync(pool.UserPoolId, username, request.Username, ct);
        return NoContent();
    }

    [HttpPost("{username}/enable")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Enable(string username, CancellationToken ct)
    {
        Audit("AdminEnableUser", username, []);
        await users.SetEnabledAsync(pool.UserPoolId, username, true, ct);
        return NoContent();
    }

    [HttpPost("{username}/disable")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Disable(string username, CancellationToken ct)
    {
        Audit("AdminDisableUser", username, []);
        await users.SetEnabledAsync(pool.UserPoolId, username, false, ct);
        return NoContent();
    }

    [HttpPost("{username}/reset-password")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ResetPassword(string username, CancellationToken ct)
    {
        Audit("AdminResetPassword", username, []);
        await users.ResetPasswordAsync(pool.UserPoolId, username, ct);

        // 202: Cognito has accepted the reset and will deliver a code out of band.
        return Accepted();
    }

    [HttpGet("{username}/groups")]
    [ProducesResponseType(typeof(GroupsResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<GroupsResponse>> GetGroups(string username, CancellationToken ct) =>
        Ok(new GroupsResponse(await users.GetGroupsAsync(pool.UserPoolId, username, ct)));

    [HttpPut("{username}/groups/{group}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddToGroup(string username, string group, CancellationToken ct)
    {
        Audit("AdminAddToGroup", username, new() { ["group"] = group });
        await users.AddToGroupAsync(pool.UserPoolId, username, group, ct);
        return NoContent();
    }

    [HttpDelete("{username}/groups/{group}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveFromGroup(string username, string group, CancellationToken ct)
    {
        Audit("AdminRemoveFromGroup", username, new() { ["group"] = group });
        await users.RemoveFromGroupAsync(pool.UserPoolId, username, group, ct);
        return NoContent();
    }

    private void Audit(string action, string target, Dictionary<string, object?> extra)
    {
        var fields = new Dictionary<string, object?>(extra)
        {
            ["actorSub"] = User.Subject(),
            ["targetUser"] = target,
        };
        audit.Record(action, fields);
    }
}
