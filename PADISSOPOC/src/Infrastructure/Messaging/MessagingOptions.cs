using System.ComponentModel.DataAnnotations;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Messaging;

/// <summary>
/// Bound from the "Messaging" configuration section. The endpoints, credentials and
/// template ids come from SSM Parameter Store, the sender address from an environment
/// variable — indistinguishable here by design.
///
/// Property names are the parameter names: <c>/padi/services/authentication/Messaging/MessagingApiUrl</c>
/// becomes the key <c>Messaging:MessagingApiUrl</c> and binds here without any mapping.
/// Renaming a property therefore means renaming the parameter too.
/// </summary>
public sealed class MessagingOptions
{
    public const string SectionName = "Messaging";

    /// <summary>The full transactional email endpoint, path included — nothing is appended.</summary>
    [Required] public string MessagingApiUrl { get; set; } = "";

    /// <summary>The OAuth2 token endpoint for the client-credentials grant.</summary>
    [Required] public string MessagingApiTokenUrl { get; set; } = "";

    [Required] public string ClientId { get; set; } = "";
    [Required] public string ClientSecret { get; set; } = "";

    public string? Scope { get; set; }
    public string? SmsUrl { get; set; }
    public string? FromAddress { get; set; }

    /// <summary>
    /// Messaging-service template ids, keyed by trigger source with the
    /// <c>CustomEmailSender_</c> prefix removed — e.g. <c>Messaging:Definitions:SignUp</c>.
    ///
    /// A <c>Default</c> entry, if present, serves any trigger source without its own key.
    /// Every trigger this sender handles delivers a verification code, so one generic
    /// template is a workable fallback and means a newly-exercised flow fails soft rather
    /// than silently sending nothing.
    /// </summary>
    public Dictionary<string, string> Definitions { get; set; } = new();
}

public sealed class OptionsTemplateCatalog(
    Microsoft.Extensions.Options.IOptionsMonitor<MessagingOptions> options) : ITemplateCatalog
{
    public string? TemplateKeyFor(string templateName)
    {
        var definitions = options.CurrentValue.Definitions;

        if (definitions.TryGetValue(templateName, out var key) && !string.IsNullOrWhiteSpace(key))
        {
            return key;
        }

        return definitions.TryGetValue(ITemplateCatalog.DefaultKey, out var fallback) && !string.IsNullOrWhiteSpace(fallback)
            ? fallback
            : null;
    }
}
