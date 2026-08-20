using Padi.Services.Authentication.Domain.MagicLink;

namespace Padi.Services.Authentication.Application.Abstractions;

/// <summary>A user as far as this service is concerned. Not a Cognito SDK type.</summary>
public sealed record DirectoryUser(string Username, IReadOnlyDictionary<string, string> Attributes)
{
    public string? Attribute(string name) => Attributes.TryGetValue(name, out var v) ? v : null;
}

public sealed record IssuedTokens(
    string? IdToken,
    string? AccessToken,
    string? RefreshToken,
    int ExpiresIn,
    string? TokenType);

public sealed record EmailRequest(
    string ContactKey,
    string TemplateKey,
    string RecipientEmail,
    IReadOnlyDictionary<string, object?> Attributes);

public sealed record SmsRequest(string PhoneNumber, string Body);

public interface IUserDirectory
{
    /// <summary>Returns null when the user does not exist. Callers must not leak that distinction.</summary>
    Task<DirectoryUser?> FindAsync(string userPoolId, string username, CancellationToken ct = default);

    Task SetAttributeAsync(string userPoolId, string username, string name, string value, CancellationToken ct = default);
}

public interface IMagicLinkTokenStore
{
    Task SaveAsync(MagicLinkToken token, CancellationToken ct = default);

    /// <summary>
    /// Atomically consumes the token, returning it only if it existed. Must be a single
    /// operation — a read-then-delete would let two concurrent redemptions both succeed.
    /// </summary>
    Task<StoredMagicLink?> ConsumeAsync(string tokenHash, CancellationToken ct = default);
}

public sealed record StoredMagicLink(string Username, DateTimeOffset ExpiresAt);

/// <summary>Completes a Cognito custom-auth exchange on the caller's behalf.</summary>
public interface IAuthenticator
{
    Task<IssuedTokens> AuthenticateAsync(string username, CancellationToken ct = default);
}

public interface IEmailSender
{
    Task SendAsync(EmailRequest request, CancellationToken ct = default);
}

public interface ISmsSender
{
    Task SendAsync(SmsRequest request, CancellationToken ct = default);
}

/// <summary>Delivers a magic link over one channel, owning how the link is presented.</summary>
public interface IMagicLinkDelivery
{
    DeliveryChannel Channel { get; }
    Task SendAsync(string destination, MagicLinkToken token, CancellationToken ct = default);
}

/// <summary>Unwraps the one-time code Cognito hands to a custom sender trigger.</summary>
public interface ICodeDecryptor
{
    string Decrypt(string ciphertext);
}

/// <summary>Maps a trigger's short name to a template id in the messaging service.</summary>
public interface ITemplateCatalog
{
    string? TemplateKeyFor(string templateName);
}

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public interface IAuditLog
{
    void Record(string eventName, IReadOnlyDictionary<string, object?> fields);
    void Warn(string message);
    void Error(string message);
}
