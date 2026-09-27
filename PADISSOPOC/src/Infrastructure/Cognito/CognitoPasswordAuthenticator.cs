using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>The pool and public app client password reset runs against — client-id-only operations.</summary>
public sealed record CognitoPasswordOptions(string UserPoolId, string ClientId);

/// <summary>
/// Password sign-in via ADMIN_USER_PASSWORD_AUTH on the server-side sign-in client.
///
/// Two things keep it off Cognito's public surface: the admin flow needs the service's IAM
/// role, and the client needs its secret. The browser's own client offers no sign-in flow at
/// all, so passwords can only be checked through this API, with its throttling and WAF.
/// </summary>
public sealed class CognitoPasswordAuthenticator(
    IAmazonCognitoIdentityProvider cognito,
    CognitoSignInClient client) : IPasswordAuthenticator
{
    public async Task<SignInOutcome> SignInAsync(
        string username, string password, CancellationToken ct = default)
    {
        AdminInitiateAuthResponse response;
        try
        {
            response = await cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
            {
                UserPoolId = client.UserPoolId,
                ClientId = client.ClientId,
                AuthFlow = AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
                AuthParameters = new Dictionary<string, string>
                {
                    ["USERNAME"] = username,
                    ["PASSWORD"] = password,
                    ["SECRET_HASH"] = await client.SecretHashAsync(username, ct),
                },
            }, ct);
        }
        catch (UserNotConfirmedException)
        {
            throw new AccountNotConfirmedException();
        }
        catch (Exception ex) when (ex is NotAuthorizedException or UserNotFoundException)
        {
            // Collapsed into one failure on purpose — see AuthenticationFailedException.
            throw new AuthenticationFailedException();
        }
        catch (PasswordResetRequiredException)
        {
            throw new AuthenticationFailedException();
        }
        catch (Exception ex) when (ex is TooManyRequestsException or LimitExceededException)
        {
            throw new TooManyAttemptsException();
        }

        // A challenge means Cognito will not issue tokens yet — MFA, a forced password
        // change, and so on. Reported rather than swallowed, so an unhandled flow is
        // visible instead of looking like a silent failure.
        if (!string.IsNullOrEmpty(response.ChallengeName?.Value))
        {
            return SignInOutcome.Challenged(response.ChallengeName.Value);
        }

        var result = response.AuthenticationResult
            ?? throw new AuthenticationFailedException();

        return SignInOutcome.Succeeded(CognitoTokens.From(result));
    }
}

internal static class CognitoTokens
{
    public static IssuedTokens From(AuthenticationResultType result) => new(
        IdToken: result.IdToken,
        AccessToken: result.AccessToken,
        RefreshToken: result.RefreshToken,
        ExpiresIn: result.ExpiresIn ?? 0,
        TokenType: result.TokenType);
}
