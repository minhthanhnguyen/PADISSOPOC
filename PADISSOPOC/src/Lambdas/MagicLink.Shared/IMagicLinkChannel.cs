namespace Padisso.MagicLink.Shared;

public enum DeliveryChannel
{
    Email,
    Sms,
}

/// <summary>
/// A delivery mechanism for magic links. Implementations own both the transport
/// (SES, SNS, …) and how the token is presented for that medium — a full URL reads
/// fine in email but is hostile in a 160-character SMS segment.
/// </summary>
public interface IMagicLinkChannel
{
    DeliveryChannel Channel { get; }

    /// <summary>Cognito standard attribute this channel delivers to, e.g. "email" / "phone_number".</summary>
    string UserAttribute { get; }

    /// <summary>Renders and sends the magic link. <paramref name="destination"/> is the resolved attribute value.</summary>
    Task SendAsync(string destination, string token);
}
