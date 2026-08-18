using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace Padi.Services.Authentication.Messaging.Http;

public sealed record EmailMessage
{
    public required string To { get; init; }
    public required string Subject { get; init; }
    public required string HtmlBody { get; init; }
    public required string TextBody { get; init; }
    /// <summary>Free-form hints (locale, brand, template id) forwarded from clientMetadata.</summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }



}

public sealed record SmsMessage
{
    public required string To { get; init; }
    public required string Body { get; init; }
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}

/// <summary>
/// Talks to the PADI messaging service. All outbound mail from this stack — Cognito
/// codes and magic links alike — goes through here, so the delivery provider is a
/// single implementation detail rather than something each caller decides.
/// </summary>
public sealed class MessagingClient(
    HttpClient http,
    BearerTokenProvider tokens,
    IOptionsMonitor<MessagingOptions> options)
{
    public Task SendEmailAsync(EmailMessage message, CancellationToken ct = default)
    {
        var o = options.CurrentValue;
        return PostAsync(o.EmailUrl, new
        {
            from = o.FromAddress,
            to = message.To,
            subject = message.Subject,
            html = message.HtmlBody,
            text = message.TextBody,
            metadata = message.Metadata,
        }, ct);
    }

    public Task SendSmsAsync(SmsMessage message, CancellationToken ct = default)
    {
        var url = options.CurrentValue.SmsUrl
                  ?? throw new InvalidOperationException("Messaging:SmsUrl is not configured.");
        return PostAsync(url, new { to = message.To, text = message.Body, metadata = message.Metadata }, ct);
    }

    private async Task PostAsync(string url, object payload, CancellationToken ct)
    {
        var token = await tokens.GetAsync(ct);

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(payload),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var res = await http.SendAsync(req, ct);
        if (res.IsSuccessStatusCode) return;

        var body = await res.Content.ReadAsStringAsync(ct);
        throw new HttpRequestException(
            $"Messaging service returned {(int)res.StatusCode} {res.ReasonPhrase}. {body}");
    }
}
