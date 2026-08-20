using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Messaging;

/// <summary>
/// Wire contract for POST /v1/email/transact. The messaging service owns the templates,
/// so this carries a definition key and substitution values, never rendered content.
/// </summary>
internal sealed record EmailProxyRequest
{
    public required string ContactKey { get; init; }
    public required string DefinitionKey { get; init; }
    public required string RecipientEmail { get; init; }
    public required IReadOnlyDictionary<string, object?> Attributes { get; init; }
}

public sealed class MessagingEmailSender(
    HttpClient http,
    BearerTokenProvider tokens,
    IOptionsMonitor<MessagingOptions> options) : IEmailSender, ISmsSender
{
    /// <summary>
    /// PascalCase on the wire to match the service contract — System.Text.Json would
    /// otherwise camelCase the property names.
    /// </summary>
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public Task SendAsync(EmailRequest request, CancellationToken ct = default) =>
        PostAsync(options.CurrentValue.EmailUrl, new EmailProxyRequest
        {
            ContactKey = request.ContactKey,
            DefinitionKey = request.TemplateKey,
            RecipientEmail = request.RecipientEmail,
            Attributes = request.Attributes,
        }, ct);

    public Task SendAsync(SmsRequest request, CancellationToken ct = default)
    {
        var url = options.CurrentValue.SmsUrl
                  ?? throw new InvalidOperationException("Messaging:SmsUrl is not configured.");
        return PostAsync(url, new { to = request.PhoneNumber, text = request.Body }, ct);
    }

    private async Task PostAsync(string url, object payload, CancellationToken ct)
    {
        var token = await tokens.GetAsync(ct);

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(payload, options: Json),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(ct);
        throw new HttpRequestException(
            $"Messaging service returned {(int)response.StatusCode} {response.ReasonPhrase}. {body}");
    }
}
