using Amazon.SimpleNotificationService.Model;
using Padisso.MagicLink.Shared;

namespace Padisso.MagicLink.Aws;

/// <summary>
/// Delivers magic links over SMS via SNS.
///
/// Deliberately terse: SMS bills per 160-character segment, and carriers are more
/// likely to filter messages containing long URLs. The link still carries the full
/// 256-bit token — shortening the token itself would trade brute-force resistance
/// for message length, which needs per-destination rate limiting first.
/// </summary>
public sealed class SmsChannel : IMagicLinkChannel
{
    public DeliveryChannel Channel => DeliveryChannel.Sms;
    public string UserAttribute => "phone_number";

    public Task SendAsync(string destination, string token)
    {
        var link = $"{Config.BaseUrl}?token={Uri.EscapeDataString(token)}";

        var request = new PublishRequest
        {
            PhoneNumber = destination,
            Message = $"Sign in ({Config.TtlMin} min): {link}",
            MessageAttributes = new Dictionary<string, MessageAttributeValue>
            {
                // Transactional prioritises delivery reliability over cost.
                ["AWS.SNS.SMS.SMSType"] = new() { DataType = "String", StringValue = "Transactional" },
            },
        };

        if (!string.IsNullOrEmpty(Config.SmsSenderId))
        {
            request.MessageAttributes["AWS.SNS.SMS.SenderID"] =
                new() { DataType = "String", StringValue = Config.SmsSenderId };
        }

        return Clients.Sns.PublishAsync(request);
    }
}
