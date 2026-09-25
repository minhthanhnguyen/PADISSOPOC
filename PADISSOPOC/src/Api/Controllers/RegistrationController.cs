using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.Users;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Self-service registration, reachable without a token — a user cannot have one before
/// their account exists.
///
/// Open routes. The unauthenticated surface is declared in one place — openRoutes in
/// PadiSsoApiStack — which lists each route and method that skips the Cognito authorizer.
/// A new action here is <i>not</i> reachable anonymously until it is added there: until then
/// the gateway sends it through the authorizer and answers 401. Do not add a route here
/// that acts on an existing account.
///
/// Every action calls Cognito's own unauthenticated operations with the app client id. Two
/// lookups use the service's IAM role (ListUsers) instead: the username availability check
/// inside sign-up, and finding a pending sign-up for resend-by-username. The second lets a
/// caller do one thing Cognito alone would not — reach an unconfirmed account by name — but
/// its only effect is a code sent to that account's own address.
/// </summary>
[ApiController]
[Route("signup")]
[AllowAnonymous]
[Produces("application/json")]
public sealed class RegistrationController(
    RegisterUser registerUser,
    ResendRegistrationCode resendRegistrationCode,
    IUserRegistration registration,
    PoolContext pool) : ControllerBase
{
    [HttpPost]
    [ProducesResponseType(typeof(RegistrationStartedResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<RegistrationStartedResponse>> SignUp(
        [FromBody] RegisterRequest request, CancellationToken ct)
    {
        var result = await registerUser.ExecuteAsync(
            new RegisterUserCommand(
                UserPoolId: pool.UserPoolId,
                Username: request.Username,
                Password: request.Password,
                Email: request.Email,
                GivenName: request.GivenName,
                MiddleInitial: request.MiddleInitial,
                FamilyName: request.FamilyName,
                Birthdate: request.Birthdate),
            ct);

        // No Location header: the account is not addressable by an anonymous caller, and
        // pointing at an admin route the caller cannot read would be misleading.
        return StatusCode(
            StatusCodes.Status201Created,
            new RegistrationStartedResponse(result.AccountId, result.Confirmed, result.CodeDestination));
    }

    [HttpPost("confirm")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Confirm(
        [FromBody] ConfirmRegistrationRequest request, CancellationToken ct)
    {
        await registration.ConfirmAsync(request.AccountId.Trim(), request.Code.Trim(), ct);
        return NoContent();
    }

    [HttpPost("resend")]
    [ProducesResponseType(typeof(CodeResentResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<CodeResentResponse>> Resend(
        [FromBody] ResendCodeRequest request, CancellationToken ct)
    {
        var destination = await registration.ResendCodeAsync(request.AccountId.Trim(), ct);
        return Accepted(new CodeResentResponse(destination));
    }

    /// <summary>
    /// Resend by the name chosen at sign-up, for a caller without the account id. Answers 202
    /// whether or not a pending sign-up exists under the name — never 404 — so it cannot be
    /// used to discover which names have one.
    /// </summary>
    [HttpPost("resend-by-username")]
    [ProducesResponseType(typeof(CodeResentResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<CodeResentResponse>> ResendByUsername(
        [FromBody] ResendCodeByUsernameRequest request, CancellationToken ct)
    {
        var destination = await resendRegistrationCode.ExecuteAsync(
            new ResendRegistrationCodeCommand(pool.UserPoolId, request.Username), ct);
        return Accepted(new CodeResentResponse(destination));
    }
}
