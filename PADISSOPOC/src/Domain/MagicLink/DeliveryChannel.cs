namespace Padi.Services.Authentication.Domain.MagicLink;

public enum DeliveryChannel
{
    Email,
    Sms,
}

public static class DeliveryChannelExtensions
{
    /// <summary>Cognito standard attribute this channel delivers to.</summary>
    public static string UserAttribute(this DeliveryChannel channel) => channel switch
    {
        DeliveryChannel.Email => "email",
        DeliveryChannel.Sms => "phone_number",
        _ => throw new ArgumentOutOfRangeException(nameof(channel)),
    };

    /// <summary>Returns null for an unrecognised name; callers treat that as a bad request.</summary>
    public static DeliveryChannel? Parse(string? name) =>
        (name ?? "email").Trim().ToLowerInvariant() switch
        {
            "email" => DeliveryChannel.Email,
            "sms" => DeliveryChannel.Sms,
            _ => null,
        };
}
