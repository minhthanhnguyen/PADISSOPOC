using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Self-service password reset, for a user who cannot sign in and therefore has no token.
///
/// Both actions use Cognito's client-id-only operations, so nothing here is possible that a
/// browser could not already do against Cognito directly. What the API adds is a single
/// throttled, audited entry point.
///
/// A password *change* by a signed-in user who knows their current password is a different
/// operation and does not belong on the public surface — it would go under `/me`.
/// </summary>
[ApiController]
[Route("public/password")]
[AllowAnonymous]
[Produces("application/json")]
public sealed class PasswordController(IPasswordReset reset, IAuditLog audit) : ControllerBase
{
    [HttpPost("forgot")]
    [ProducesResponseType(typeof(PasswordResetStartedResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<PasswordResetStartedResponse>> Forgot(
        [FromBody] ForgotPasswordRequest request, CancellationToken ct)
    {
        var username = request.Username.Trim();
        var destination = await reset.StartAsync(username, ct);

        audit.Record("PasswordResetRequested", new Dictionary<string, object?>
        {
            ["username"] = username,
        });

        // 202 regardless of whether the account exists. Cognito fabricates a destination
        // for an unknown user, so this response reveals nothing either way.
        return Accepted(new PasswordResetStartedResponse(destination));
    }

    [HttpPost("reset")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Reset(
        [FromBody] ResetPasswordRequest request, CancellationToken ct)
    {
        var username = request.Username.Trim();
        await reset.CompleteAsync(username, request.Code.Trim(), request.NewPassword, ct);

        // Recorded after the fact, unlike the admin routes: a failed attempt here is a
        // wrong code rather than a privileged action, and logging every guess would fill
        // the audit trail with noise.
        audit.Record("PasswordReset", new Dictionary<string, object?>
        {
            ["username"] = username,
        });

        return NoContent();
    }
}
