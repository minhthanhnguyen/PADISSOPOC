using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// Refresh and sign-out for tokens issued on the sign-in client. Both need the client's
/// secret, so the browser relies on the API for them.
/// </summary>
public sealed class CognitoSessionTokens(
    IAmazonCognitoIdentityProvider cognito,
    CognitoSignInClient client) : ISessionTokens
{
    public async Task<IssuedTokens> RefreshAsync(
        string username, string refreshToken, CancellationToken ct = default)
    {
        try
        {
            var response = await cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
            {
                UserPoolId = client.UserPoolId,
                ClientId = client.ClientId,
                AuthFlow = AuthFlowType.REFRESH_TOKEN_AUTH,
                AuthParameters = new Dictionary<string, string>
                {
                    ["REFRESH_TOKEN"] = refreshToken,
                    // For a refresh, Cognito keys the hash on the username claim — not an
                    // alias — because username is one of this pool's sign-in attributes.
                    ["SECRET_HASH"] = await client.SecretHashAsync(username, ct),
                },
            }, ct);

            var result = response.AuthenticationResult
                ?? throw new ChallengeFailedException("The session could not be refreshed. Sign in again.");

            // Cognito returns no new refresh token unless rotation is on; the caller keeps
            // the one it has.
            return CognitoTokens.From(result);
        }
        catch (Exception ex) when (ex is NotAuthorizedException or UserNotFoundException)
        {
            // Expired or revoked refresh token, a disabled user, or a username that does not
            // match the token — all mean the same thing to the caller.
            throw new ChallengeFailedException("The session could not be refreshed. Sign in again.");
        }
        catch (Exception ex) when (ex is TooManyRequestsException or LimitExceededException)
        {
            throw new TooManyAttemptsException();
        }
    }

    public async Task RevokeAsync(string refreshToken, CancellationToken ct = default)
    {
        try
        {
            await cognito.RevokeTokenAsync(new RevokeTokenRequest
            {
                Token = refreshToken,
                ClientId = client.ClientId,
                ClientSecret = await client.SecretAsync(ct),
            }, ct);
        }
        catch (Exception ex) when (ex is UnauthorizedException or UnsupportedTokenTypeException)
        {
            // Already revoked, expired, or not a refresh token from this client. Sign-out is
            // idempotent, so there is nothing to report.
        }
    }
}
