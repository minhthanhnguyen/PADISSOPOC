using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.MagicLink;

namespace Padi.Services.Authentication.Infrastructure.Notifications;

public sealed record MagicLinkDeliveryOptions
{
    public required string BaseUrl { get; init; }
    public required string FromAddress { get; init; }
    public string? SmsSenderId { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(15);

    public string LinkFor(MagicLinkToken token) => $"{BaseUrl}?token={Uri.EscapeDataString(token.Raw)}";
}

public sealed class SesMagicLinkDelivery(IAmazonSimpleEmailServiceV2 ses, MagicLinkDeliveryOptions options)
    : IMagicLinkDelivery
{
    public DeliveryChannel Channel => DeliveryChannel.Email;

    public Task SendAsync(string destination, MagicLinkToken token, CancellationToken ct = default)
    {
        var link = options.LinkFor(token);
        var minutes = (int)options.Lifetime.TotalMinutes;

        return ses.SendEmailAsync(new SendEmailRequest
        {
            FromEmailAddress = options.FromAddress,
            Destination = new Destination { ToAddresses = [destination] },
            Content = new EmailContent
            {
                Simple = new Message
                {
                    Subject = new Content { Data = "Your sign-in link" },
                    Body = new Body
                    {
                        Text = new Content { Data = $"Click to sign in (expires in {minutes} min):\n\n{link}" },
                        Html = new Content
                        {
                            Data = $"<p>Click to sign in (expires in {minutes} min):</p>" +
                                   $"<p><a href=\"{link}\">Sign in</a></p>",
                        },
                    },
                },
            },
        }, ct);
    }
}

/// <summary>
/// Deliberately terse: SMS bills per 160-character segment and carriers are more likely
/// to filter messages carrying long URLs. The token keeps its full entropy — shortening it
/// would trade brute-force resistance for message length, which needs per-destination
/// rate limiting first.
/// </summary>
public sealed class SnsMagicLinkDelivery(IAmazonSimpleNotificationService sns, MagicLinkDeliveryOptions options)
    : IMagicLinkDelivery
{
    public DeliveryChannel Channel => DeliveryChannel.Sms;

    public Task SendAsync(string destination, MagicLinkToken token, CancellationToken ct = default)
    {
        var request = new PublishRequest
        {
            PhoneNumber = destination,
            Message = $"Sign in ({(int)options.Lifetime.TotalMinutes} min): {options.LinkFor(token)}",
            MessageAttributes = new Dictionary<string, MessageAttributeValue>
            {
                ["AWS.SNS.SMS.SMSType"] = new() { DataType = "String", StringValue = "Transactional" },
            },
        };

        if (!string.IsNullOrEmpty(options.SmsSenderId))
        {
            request.MessageAttributes["AWS.SNS.SMS.SenderID"] =
                new() { DataType = "String", StringValue = options.SmsSenderId };
        }

        return sns.PublishAsync(request, ct);
    }
}
