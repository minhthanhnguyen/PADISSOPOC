using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>The pool and app client the password flows — sign-in and reset — run against.</summary>
public sealed record CognitoPasswordOptions(string UserPoolId, string ClientId);

/// <summary>
/// Password sign-in via ADMIN_USER_PASSWORD_AUTH.
///
/// This is an admin operation and needs the service's IAM role, which is the reason for
/// choosing it over USER_PASSWORD_AUTH: enabling the latter on the app client would let
/// anyone holding the public client id perform plaintext authentication against Cognito
/// directly, bypassing this API along with its throttling and WAF.
/// </summary>
public sealed class CognitoPasswordAuthenticator(
    IAmazonCognitoIdentityProvider cognito,
    CognitoPasswordOptions options) : IPasswordAuthenticator
{
    public async Task<SignInOutcome> SignInAsync(
        string username, string password, CancellationToken ct = default)
    {
        AdminInitiateAuthResponse response;
        try
        {
            response = await cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
            {
                UserPoolId = options.UserPoolId,
                ClientId = options.ClientId,
                AuthFlow = AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
                AuthParameters = new Dictionary<string, string>
                {
                    ["USERNAME"] = username,
                    ["PASSWORD"] = password,
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

        // A challenge means Cognito will not issue tokens yet — MFA, a forced password
        // change, and so on. Reported rather than swallowed, so an unhandled flow is
        // visible instead of looking like a silent failure.
        if (!string.IsNullOrEmpty(response.ChallengeName?.Value))
        {
            return SignInOutcome.Challenged(response.ChallengeName.Value);
        }

        var result = response.AuthenticationResult
            ?? throw new AuthenticationFailedException();

        return SignInOutcome.Succeeded(new IssuedTokens(
            IdToken: result.IdToken,
            AccessToken: result.AccessToken,
            RefreshToken: result.RefreshToken,
            ExpiresIn: result.ExpiresIn ?? 0,
            TokenType: result.TokenType));
    }
}
