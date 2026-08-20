using System.Security.Cryptography;
using System.Text;

namespace Padi.Services.Authentication.Domain.MagicLink;

/// <summary>
/// A single-use sign-in token. The raw value exists only long enough to be delivered;
/// only <see cref="Hash"/> is ever persisted, so a leaked store cannot be replayed.
/// </summary>
public sealed record MagicLinkToken
{
    private MagicLinkToken(string raw, string hash, string username, DeliveryChannel channel, DateTimeOffset expiresAt)
    {
        Raw = raw;
        Hash = hash;
        Username = username;
        Channel = channel;
        ExpiresAt = expiresAt;
    }

    public string Raw { get; }
    public string Hash { get; }
    public string Username { get; }
    public DeliveryChannel Channel { get; }
    public DateTimeOffset ExpiresAt { get; }

    public static MagicLinkToken Issue(string username, DeliveryChannel channel, DateTimeOffset now, TimeSpan lifetime)
    {
        var raw = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        return new MagicLinkToken(raw, HashOf(raw), username, channel, now.Add(lifetime));
    }

    /// <summary>256 bits, hex-encoded. Wide enough that guessing is not a threat model.</summary>
    public static string HashOf(string rawToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))).ToLowerInvariant();

    public bool IsExpiredAt(DateTimeOffset now) => now >= ExpiresAt;
}
