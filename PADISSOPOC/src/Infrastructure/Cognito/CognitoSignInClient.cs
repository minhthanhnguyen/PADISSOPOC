using System.Security.Cryptography;
using System.Text;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// The server-side app client every API sign-in runs on. It has a client secret, so Cognito
/// rejects any sign-in call on it without a SECRET_HASH — which makes its client id useless
/// to anyone but this service.
///
/// The secret is read from Cognito on first use (DescribeUserPoolClient, under the service's
/// IAM role) and held in memory. It is never in configuration or an environment variable.
/// </summary>
public sealed class CognitoSignInClient(IAmazonCognitoIdentityProvider cognito, string userPoolId, string clientId)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _secret;

    public string UserPoolId { get; } = userPoolId;

    public string ClientId { get; } = clientId;

    /// <summary>SECRET_HASH for <paramref name="username"/> on this client.</summary>
    public async Task<string> SecretHashAsync(string username, CancellationToken ct = default) =>
        SecretHash.Compute(await SecretAsync(ct), username, ClientId);

    public async Task<string> SecretAsync(CancellationToken ct = default)
    {
        if (_secret is not null)
        {
            return _secret;
        }

        await _gate.WaitAsync(ct);
        try
        {
            // A failed read is not cached: the next call tries again.
            return _secret ??= (await cognito.DescribeUserPoolClientAsync(new DescribeUserPoolClientRequest
            {
                UserPoolId = UserPoolId,
                ClientId = ClientId,
            }, ct)).UserPoolClient.ClientSecret;
        }
        finally
        {
            _gate.Release();
        }
    }
}

public static class SecretHash
{
    /// <summary>Base64(HMAC-SHA256(key: client secret, message: username + client id)).</summary>
    public static string Compute(string clientSecret, string username, string clientId) =>
        Convert.ToBase64String(HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(clientSecret),
            Encoding.UTF8.GetBytes(username + clientId)));
}
