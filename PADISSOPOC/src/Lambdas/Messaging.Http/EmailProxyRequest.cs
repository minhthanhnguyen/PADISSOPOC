namespace Padi.Services.Authentication.Messaging.Http;

/// <summary>
/// Wire contract for POST /v1/email/transact.
///
/// The messaging service owns the templates: this sends a definition key and the
/// substitution values, not rendered content. Subjects and bodies therefore live in
/// the messaging service, not in this repository.
/// </summary>
public sealed record EmailProxyRequest
{
    /// <summary>Stable identifier for the recipient. Cognito's <c>sub</c> is used.</summary>
    public required string ContactKey { get; init; }

    /// <summary>Template identifier registered in the messaging service.</summary>
    public required string DefinitionKey { get; init; }

    public required string RecipientEmail { get; init; }

    /// <summary>
    /// Template substitution values. Declared as a dictionary rather than <c>dynamic</c> —
    /// it serialises to the same JSON, but avoids the runtime binder and keeps the type
    /// checkable at compile time.
    /// </summary>
    public IReadOnlyDictionary<string, object?> Attributes { get; init; }
        = new Dictionary<string, object?>();
}
