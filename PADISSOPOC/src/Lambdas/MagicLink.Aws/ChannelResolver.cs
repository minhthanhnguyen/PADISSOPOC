using Padi.Services.Authentication.MagicLink.Shared;

namespace Padi.Services.Authentication.MagicLink.Aws;

/// <summary>
/// Maps a caller-supplied channel name to an implementation.
/// Resolution is explicit rather than inferred from which attributes the user has —
/// a user with both an email and a phone number would otherwise be ambiguous.
/// </summary>
public static class ChannelResolver
{
    private static readonly SesEmailChannel Email = new();
    private static readonly SmsChannel Sms = new();

    public const string DefaultChannel = "email";

    /// <summary>Returns null when the name is not a supported channel.</summary>
    public static IMagicLinkChannel? Resolve(string? name) =>
        (name ?? DefaultChannel).Trim().ToLowerInvariant() switch
        {
            "email" => Email,
            "sms"   => Sms,
            _       => null,
        };
}
