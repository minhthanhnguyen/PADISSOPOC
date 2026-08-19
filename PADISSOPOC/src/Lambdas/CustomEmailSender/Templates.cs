using System.Text.Json.Nodes;

namespace Padi.Services.Authentication.Cognito.CustomEmailSender;

/// <summary>
/// Builds the substitution values sent to the messaging service.
///
/// Subjects and bodies live in the messaging service's template definitions, so this
/// only assembles the attributes those templates reference. The definition id itself
/// comes from configuration (<c>Messaging:Definitions:*</c>), keyed by trigger source.
/// </summary>
public static class Templates
{
    /// <summary>Strips the <c>CustomEmailSender_</c> prefix to give the configuration key.</summary>
    public static string? DefinitionKeyFor(string triggerSource) =>
        triggerSource.StartsWith("CustomEmailSender_", StringComparison.Ordinal)
            ? triggerSource["CustomEmailSender_".Length..]
            : null;

    public static Dictionary<string, object?> AttributesFor(
        string triggerSource,
        string? code,
        string email,
        JsonObject? userAttributes,
        IReadOnlyDictionary<string, string>? clientMetadata)
    {
        var attrs = new Dictionary<string, object?>
        {            
            ["SubscriberKey"]       = email,
            ["EmailAddress"]        = email,
            ["VerificationCode"]    = code,
            ["LanguageCode"]        = Attr(userAttributes, "custom:language") ?? "en-US",
            ["FirstName"]           = Attr(userAttributes, "given_name"),
            ["META_COUNTRY_CODE"]   = "US",
        };

        // Anything the client passed through ClientMetadata (locale, brand, campaign)
        // is forwarded so templates can vary on it without a code change.
        if (clientMetadata is not null)
        {
            foreach (var (k, v) in clientMetadata)
            {
                attrs[k] = v;
            }
        }

        return attrs;
    }

    private static string? Attr(JsonObject? attrs, string name) => attrs?[name]?.GetValue<string>();
}
