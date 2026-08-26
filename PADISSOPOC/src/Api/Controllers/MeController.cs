using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.Users;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Operations a signed-in user performs on their own account.
///
/// No action takes a user identifier. The account acted on is always the one the bearer
/// token belongs to, so there is no route shape a caller could use to reach someone else's
/// account even if the authorization policy were misconfigured.
/// </summary>
[ApiController]
[Route("me")]
[Authorize(Policy = Policies.Caller)]
[Produces("application/json")]
public sealed class MeController(IUserSelfService users, ChangeUsername changeUsername) : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<ProfileResponse>> Get(CancellationToken ct) =>
        await ReadProfile(ct);

    [HttpPatch]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<ProfileResponse>> UpdateProfile(
        [FromBody] UpdateProfileRequest request, CancellationToken ct)
    {
        var attributes = new Dictionary<string, string>();
        if (request.GivenName is not null)
        {
            attributes["given_name"] = request.GivenName.Trim();
        }
        if (request.FamilyName is not null)
        {
            attributes["family_name"] = request.FamilyName.Trim();
        }

        // A body with every field omitted is structurally valid but means nothing.
        if (attributes.Count == 0)
        {
            return Problem(
                title: "Nothing to update.",
                detail: "Supply givenName, familyName, or both.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        await users.UpdateAttributesAsync(HttpContext.AccessToken(), attributes, ct);
        return await ReadProfile(ct);
    }

    [HttpPut("username")]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<ProfileResponse>> ChangeUsername(
        [FromBody] ChangeUsernameRequest request, CancellationToken ct)
    {
        await changeUsername.ExecuteAsync(HttpContext.AccessToken(), request.Username, ct);
        return await ReadProfile(ct);
    }

    [HttpPut("email")]
    [ProducesResponseType(typeof(EmailChangeStartedResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<EmailChangeStartedResponse>> ChangeEmail(
        [FromBody] ChangeEmailRequest request, CancellationToken ct)
    {
        var destination = await users.StartEmailChangeAsync(
            HttpContext.AccessToken(), request.Email.Trim(), ct);

        // 202, not 200: the address has not changed yet. The pool keeps the current one
        // active until the code is confirmed below.
        return Accepted(new EmailChangeStartedResponse(destination));
    }

    [HttpPost("email/confirm")]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<ProfileResponse>> ConfirmEmail(
        [FromBody] ConfirmEmailRequest request, CancellationToken ct)
    {
        await users.ConfirmEmailChangeAsync(HttpContext.AccessToken(), request.Code.Trim(), ct);
        return await ReadProfile(ct);
    }

    private async Task<ActionResult<ProfileResponse>> ReadProfile(CancellationToken ct)
    {
        var attributes = await users.GetAsync(HttpContext.AccessToken(), ct);
        return Ok(ProfileResponse.From(attributes));
    }
}
