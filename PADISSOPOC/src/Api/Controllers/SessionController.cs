using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Padi.Services.Authentication.Api.Contracts;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api.Controllers;

/// <summary>
/// Every way of signing in, refreshing a session and signing out. Anonymous by necessity — a
/// token is what these produce.
///
/// This controller is the only way to sign in. All of it runs on the server-side sign-in
/// client, which has a secret; the browser's own app client offers no sign-in flow. So
/// passwords, codes and passkey assertions reach Cognito only through here, behind the
/// gateway's throttling and any WAF placed in front of it.
///
/// Open routes: each action is listed in the gateway's openRoutes in PadiSsoApiStack. Unlike
/// the registration routes these do act on an existing account, but only for a caller who
/// proves control of it — a password, a code, a passkey or a refresh token.
/// </summary>
[ApiController]
[AllowAnonymous]
[Produces("application/json")]
public sealed class SessionController(
    IPasswordAuthenticator passwords,
    IPasswordlessSignIn passwordless,
    ISessionTokens sessions,
    IAuditLog audit) : ControllerBase
{
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<LoginResponse>> Login(
        [FromBody] LoginRequest request, CancellationToken ct)
    {
        var username = request.Username.Trim();
        return Issued(username, "password", await passwords.SignInAsync(username, request.Password, ct));
    }

    /// <summary>
    /// Starts passwordless sign-in: Cognito emails or texts a code, or returns WebAuthn options
    /// for the browser to sign with a passkey.
    /// </summary>
    [HttpPost("login/challenge")]
    [ProducesResponseType(typeof(ChallengeStartedResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<ChallengeStartedResponse>> StartChallenge(
        [FromBody] StartChallengeRequest request, CancellationToken ct)
    {
        var challenge = await passwordless.StartAsync(request.Username.Trim(), ParseFactor(request.Factor), ct);

        return Ok(new ChallengeStartedResponse(
            request.Factor, challenge.Session, challenge.CodeDestination, challenge.CredentialRequestOptions));
    }

    /// <summary>Completes passwordless sign-in with the code or the passkey assertion.</summary>
    [HttpPost("login/challenge/answer")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<LoginResponse>> AnswerChallenge(
        [FromBody] AnswerChallengeRequest request, CancellationToken ct)
    {
        var username = request.Username.Trim();
        var factor = ParseFactor(request.Factor);
        var outcome = await passwordless.AnswerAsync(
            username, factor, request.Session, request.Answer.Trim(), ct);

        return Issued(username, request.Factor, outcome);
    }

    /// <summary>
    /// New ID and access tokens for a refresh token. The browser cannot refresh on its own:
    /// the tokens come from a client with a secret.
    /// </summary>
    [HttpPost("token/refresh")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<LoginResponse>> Refresh(
        [FromBody] RefreshTokensRequest request, CancellationToken ct) =>
        Ok(LoginResponse.From(await sessions.RefreshAsync(request.Username.Trim(), request.RefreshToken, ct)));

    /// <summary>
    /// Revokes the refresh token and every access token issued from it. Always 204: signing
    /// out a session that is already gone is not an error.
    /// </summary>
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request, CancellationToken ct)
    {
        await sessions.RevokeAsync(request.RefreshToken, ct);
        return NoContent();
    }

    private ActionResult<LoginResponse> Issued(string username, string method, SignInOutcome outcome)
    {
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

        // The username and method are recorded, never a credential or a token.
        audit.Record("SignInIssued", new Dictionary<string, object?>
        {
            ["username"] = username,
            ["method"] = method,
        });

        return Ok(LoginResponse.From(outcome.Tokens!));
    }

    /// <summary>The request's pattern annotation has already restricted the value.</summary>
    private static PasswordlessFactor ParseFactor(string factor) => factor switch
    {
        "EMAIL_OTP" => PasswordlessFactor.EmailOtp,
        "SMS_OTP" => PasswordlessFactor.SmsOtp,
        _ => PasswordlessFactor.Passkey,
    };
}
