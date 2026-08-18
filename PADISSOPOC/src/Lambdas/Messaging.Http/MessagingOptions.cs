using System.ComponentModel.DataAnnotations;

namespace Padi.Services.Authentication.Messaging.Http;

/// <summary>
/// Bound from the "Messaging" configuration section. Values arrive from two sources
/// transparently: non-secret settings from environment variables (<c>Messaging__EmailUrl</c>),
/// credentials from SSM Parameter Store (<c>/padi/services/authentication/Messaging/ClientId</c>).
/// Consumers do not know or care which is which.
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
}
