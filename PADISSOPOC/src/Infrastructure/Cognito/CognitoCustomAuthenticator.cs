using System.Security.Cryptography;
using System.Text;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

public sealed record CognitoAuthOptions
{
    public required string UserPoolId { get; init; }

    /// <summary>The server-only magic-link app client — never the public browser client.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// That client's secret. Cognito rejects any call on the client without a SECRET_HASH
    /// derived from it, so knowing the client id is not enough to start its custom-auth flow.
    /// </summary>
    public required string ClientSecret { get; init; }

    /// <summary>
    /// Shared with the VerifyAuthChallenge trigger. It proves the challenge came from this
    /// component rather than standing in for the user's own credentials, which were
    /// already checked.
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
        var secretHash = SecretHash(username);

        var initiated = await cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
        {
            UserPoolId = options.UserPoolId,
            ClientId = options.ClientId,
            AuthFlow = AuthFlowType.CUSTOM_AUTH,
            AuthParameters = new Dictionary<string, string>
            {
                ["USERNAME"] = username,
                ["SECRET_HASH"] = secretHash,
            },
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
                ["SECRET_HASH"] = secretHash,
            },
            ClientMetadata = metadata,
        }, ct);

        var result = responded.AuthenticationResult;
        return new IssuedTokens(
            result.IdToken, result.AccessToken, result.RefreshToken, result.ExpiresIn ?? 0, result.TokenType);
    }

    /// <summary>Base64 HMAC-SHA256 of username + client id, keyed by the client secret.</summary>
    private string SecretHash(string username) =>
        Convert.ToBase64String(HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(options.ClientSecret),
            Encoding.UTF8.GetBytes(username + options.ClientId)));
}
