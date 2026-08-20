using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace Padi.Services.Authentication.Infrastructure.Messaging;

/// <summary>
/// OAuth2 client-credentials token, cached for the life of the execution environment.
/// Read through IOptionsMonitor so a credential rotated in Parameter Store is picked up
/// on the next refresh without a redeploy.
/// </summary>
public sealed class BearerTokenProvider(HttpClient http, IOptionsMonitor<MessagingOptions> options)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _token;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    /// <summary>Refresh this far ahead of expiry so an in-flight request never uses a stale token.</summary>
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);

    public async Task<string> GetAsync(CancellationToken ct = default)
    {
        if (Fresh(out var cached))
        {
            return cached;
        }

        await _gate.WaitAsync(ct);
        try
        {
            if (Fresh(out cached))
            {
                return cached;
            }

            var o = options.CurrentValue;

            // JSON body rather than the more usual application/x-www-form-urlencoded —
            // this is what the PADI token endpoint expects.
            var tokenRequest = new Dictionary<string, string> { ["grant_type"] = "client_credentials" };
            if (!string.IsNullOrWhiteSpace(o.Scope))
            {
                tokenRequest["scope"] = o.Scope;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, o.TokenUrl)
            {
                Content = JsonContent.Create(tokenRequest),
            };
            // client_secret_basic — credentials go in the header, not the JSON body.
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{o.ClientId}:{o.ClientSecret}")));

            using var response = await http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException(
                    $"Token request failed: {(int)response.StatusCode} {response.ReasonPhrase}. {error}");
            }

            var payload = await response.Content.ReadFromJsonAsync<TokenResponse>(ct)
                          ?? throw new InvalidOperationException("Empty token response.");

            _token = payload.AccessToken;
            _expiresAt = DateTimeOffset.UtcNow.AddSeconds(payload.ExpiresIn <= 0 ? 3600 : payload.ExpiresIn);
            return _token;
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool Fresh(out string token)
    {
        if (_token is not null && DateTimeOffset.UtcNow < _expiresAt - Skew)
        {
            token = _token;
            return true;
        }

        token = "";
        return false;
    }

    private sealed record TokenResponse
    {
        [JsonPropertyName("access_token")] public string AccessToken { get; init; } = "";
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; init; }
    }
}
