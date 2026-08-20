using System.ComponentModel.DataAnnotations;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Messaging;

/// <summary>
/// Bound from the "Messaging" configuration section. Non-secret settings arrive as
/// environment variables, credentials from SSM Parameter Store — indistinguishable here
/// by design.
/// </summary>
public sealed class MessagingOptions
{
    public const string SectionName = "Messaging";

    [Required] public string EmailUrl { get; set; } = "";
    [Required] public string TokenUrl { get; set; } = "";
    [Required] public string ClientId { get; set; } = "";
    [Required] public string ClientSecret { get; set; } = "";

    public string? Scope { get; set; }
    public string? SmsUrl { get; set; }
    public string? FromAddress { get; set; }

    /// <summary>
    /// Messaging-service template ids, keyed by trigger source with the
    /// <c>CustomEmailSender_</c> prefix removed — e.g. <c>Messaging:Definitions:SignUp</c>.
    /// </summary>
    public Dictionary<string, string> Definitions { get; set; } = new();
}

public sealed class OptionsTemplateCatalog(
    Microsoft.Extensions.Options.IOptionsMonitor<MessagingOptions> options) : ITemplateCatalog
{
    public string? TemplateKeyFor(string templateName) =>
        options.CurrentValue.Definitions.TryGetValue(templateName, out var key) && !string.IsNullOrWhiteSpace(key)
            ? key
            : null;
}
