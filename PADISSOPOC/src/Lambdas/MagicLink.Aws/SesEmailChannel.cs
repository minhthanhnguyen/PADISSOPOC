using Amazon.SimpleEmailV2.Model;
using Padisso.MagicLink.Shared;

namespace Padisso.MagicLink.Aws;

/// <summary>Delivers magic links as a clickable URL over SES.</summary>
public sealed class SesEmailChannel : IMagicLinkChannel
{
    public DeliveryChannel Channel => DeliveryChannel.Email;
    public string UserAttribute => "email";

    public Task SendAsync(string destination, string token)
    {
        var link = $"{Config.BaseUrl}?token={Uri.EscapeDataString(token)}";
        var ttl  = Config.TtlMin;

        return Clients.Ses.SendEmailAsync(new SendEmailRequest
        {
            FromEmailAddress = Config.EmailFrom,
            Destination = new Destination { ToAddresses = new List<string> { destination } },
            Content = new EmailContent
            {
                Simple = new Message
                {
                    Subject = new Content { Data = "Your sign-in link" },
                    Body = new Body
                    {
                        Text = new Content { Data = $"Click to sign in (expires in {ttl} min):\n\n{link}" },
                        Html = new Content { Data = $"<p>Click to sign in (expires in {ttl} min):</p><p><a href=\"{link}\">Sign in</a></p>" },
                    },
                },
            },
        });
    }
}
