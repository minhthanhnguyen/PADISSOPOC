using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.MagicLink;

namespace Padi.Services.Authentication.Application.MagicLink;

public sealed record RequestMagicLinkCommand(string UserPoolId, string Username, DeliveryChannel Channel);

/// <summary>
/// Issues a magic link over the requested channel.
///
/// Completes silently when the user does not exist or has no contact value for that
/// channel. Callers must return the same response either way — distinguishing the cases
/// would turn this endpoint into a user-enumeration oracle.
/// </summary>
public sealed class RequestMagicLink(
    IUserDirectory directory,
    IMagicLinkTokenStore store,
    IEnumerable<IMagicLinkDelivery> deliveries,
    IClock clock)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    public async Task ExecuteAsync(RequestMagicLinkCommand command, CancellationToken ct = default)
    {
        var user = await directory.FindAsync(command.UserPoolId, command.Username, ct);
        if (user is null)
        {
            return;
        }

        var destination = user.Attribute(command.Channel.UserAttribute());
        if (string.IsNullOrEmpty(destination))
        {
            return;
        }

        var delivery = deliveries.FirstOrDefault(d => d.Channel == command.Channel)
            ?? throw new InvalidOperationException($"No delivery registered for {command.Channel}.");

        var token = MagicLinkToken.Issue(command.Username, command.Channel, clock.UtcNow, Lifetime);

        // Persisted before sending: a token the user receives but cannot redeem is worse
        // than one stored and never delivered.
        await store.SaveAsync(token, ct);
        await delivery.SendAsync(destination, token, ct);
    }
}
