using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Password sign-in. Anonymous by necessity — a token is what this produces.
///
/// An open route: listed in the gateway's openRoutes in PadiSsoApiStack, the one place the
/// unauthenticated surface is declared. Unlike the registration routes it *does* act on an
/// existing account, but only for a caller who proves control of it with the password.
/// </summary>
[ApiController]
[Route("login")]
[AllowAnonymous]
[Produces("application/json")]
public sealed class SessionController(IPasswordAuthenticator authenticator, IAuditLog audit) : ControllerBase
{
    [HttpPost]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<LoginResponse>> Login(
        [FromBody] LoginRequest request, CancellationToken ct)
    {
        var outcome = await authenticator.SignInAsync(request.Username.Trim(), request.Password, ct);

        if (outcome.Challenge is not null)
        {
            // Cognito wants something else first — MFA, a forced password change. Named
            // explicitly rather than reported as a generic failure, because "sign-in did
            // not work" for an unimplemented challenge is nearly impossible to diagnose.
            return Problem(
                title: "This account requires an additional step that is not supported yet.",
                detail: outcome.Challenge,
                statusCode: StatusCodes.Status400BadRequest);
        }

        var tokens = outcome.Tokens!;

        // The username is recorded, never the password or the tokens.
        audit.Record("SignInIssued", new Dictionary<string, object?>
        {
            ["username"] = request.Username.Trim(),
        });

        return Ok(new LoginResponse(
            tokens.IdToken,
            tokens.AccessToken,
            tokens.RefreshToken,
            tokens.ExpiresIn,
            tokens.TokenType));
    }
}
