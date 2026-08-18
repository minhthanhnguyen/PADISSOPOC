using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace Padi.Services.Authentication.Messaging.Http;

/// <summary>
/// Fetches and caches an OAuth2 client-credentials access token for the messaging service.
/// Registered as a singleton, so the cache spans warm invocations.
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
        if (Fresh(out var cached)) return cached;

        await _gate.WaitAsync(ct);
        try
        {
            if (Fresh(out cached)) return cached;

            // Read through IOptionsMonitor so a credential rotated in Parameter Store is
            // picked up on the next token refresh without a redeploy.
            var o = options.CurrentValue;

            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials"),
            };
            if (!string.IsNullOrWhiteSpace(o.Scope))
                form.Add(new KeyValuePair<string, string>("scope", o.Scope));

            using var req = new HttpRequestMessage(HttpMethod.Post, o.TokenUrl)
            {
                Content = new FormUrlEncodedContent(form),
            };
            // client_secret_basic — the form-post variant is also common; swap if the
            // service rejects this with invalid_client.
            req.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes($"{o.ClientId}:{o.ClientSecret}")));

            using var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException(
                    $"Token request failed: {(int)res.StatusCode} {res.ReasonPhrase}. {body}");
            }

            var payload = await res.Content.ReadFromJsonAsync<TokenResponse>(ct)
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
        [JsonPropertyName("expires_in")]   public int ExpiresIn { get; init; }
    }
}
