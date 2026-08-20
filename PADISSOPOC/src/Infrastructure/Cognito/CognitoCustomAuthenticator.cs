using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

public sealed record CognitoAuthOptions
{
    public required string UserPoolId { get; init; }
    public required string ClientId { get; init; }

    /// <summary>
    /// Shared with the VerifyAuthChallenge trigger. It proves the challenge came from this
    /// component — the only principal permitted to call AdminInitiateAuth on the pool —
    /// rather than standing in for the user's own credentials, which were already checked.
    /// </summary>
    public required string AdminProof { get; init; }
}

/// <summary>
/// Drives Cognito's custom-auth exchange server-side. Because the session never leaves
/// this process, its short lifetime places no limit on how long a magic link stays valid.
/// </summary>
public sealed class CognitoCustomAuthenticator(
    IAmazonCognitoIdentityProvider cognito,
    CognitoAuthOptions options) : IAuthenticator
{
    public async Task<IssuedTokens> AuthenticateAsync(string username, CancellationToken ct = default)
    {
        var metadata = new Dictionary<string, string> { ["admin_proof"] = options.AdminProof };

        var initiated = await cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
        {
            UserPoolId = options.UserPoolId,
            ClientId = options.ClientId,
            AuthFlow = AuthFlowType.CUSTOM_AUTH,
            AuthParameters = new Dictionary<string, string> { ["USERNAME"] = username },
            ClientMetadata = metadata,
        }, ct);

        var responded = await cognito.AdminRespondToAuthChallengeAsync(new AdminRespondToAuthChallengeRequest
        {
            UserPoolId = options.UserPoolId,
            ClientId = options.ClientId,
            ChallengeName = ChallengeNameType.CUSTOM_CHALLENGE,
            Session = initiated.Session,
            ChallengeResponses = new Dictionary<string, string>
            {
                ["USERNAME"] = username,
                ["ANSWER"] = options.AdminProof,
            },
            ClientMetadata = metadata,
        }, ct);

        var result = responded.AuthenticationResult;
        return new IssuedTokens(
            result.IdToken, result.AccessToken, result.RefreshToken, result.ExpiresIn ?? 0, result.TokenType);
    }
}
