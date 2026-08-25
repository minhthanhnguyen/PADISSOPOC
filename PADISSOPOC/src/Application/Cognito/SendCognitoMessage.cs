using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.Cognito;

namespace Padi.Services.Authentication.Application.Cognito;

public sealed record CognitoMessageCommand(
    CognitoTriggerSource TriggerSource,
    string? EncryptedCode,
    IReadOnlyDictionary<string, string> UserAttributes,
    IReadOnlyDictionary<string, string>? ClientMetadata);

/// <summary>
/// Delivers a Cognito-originated message through the messaging service.
///
/// Cognito sends nothing itself once the custom sender trigger is attached, so a failure
/// here means the user never receives their code. Genuine delivery failures are therefore
/// allowed to surface; only *absent configuration* is treated as a skip.
/// </summary>
public sealed class SendCognitoMessage(
    ICodeDecryptor decryptor,
    ITemplateCatalog templates,
    IEmailSender email,
    IAuditLog audit)
{
    public async Task ExecuteAsync(CognitoMessageCommand command, CancellationToken ct = default)
    {
        if (!command.UserAttributes.TryGetValue("email", out var recipient) || string.IsNullOrEmpty(recipient))
        {
            audit.Warn($"{command.TriggerSource}: user has no email attribute; nothing sent.");
            return;
        }

        var templateName = command.TriggerSource.TemplateName;
        var templateKey = templateName is null ? null : templates.TemplateKeyFor(templateName);
        if (string.IsNullOrWhiteSpace(templateKey))
        {
            // An unconfigured template must not block the Cognito operation that caused it.
            // Cognito still reports success to the caller, so this warning is the only
            // signal that a user was told a code was sent and never received one — name
            // the missing key so the cause is obvious from the log line alone.
            audit.Warn(
                $"No template configured for '{templateName ?? command.TriggerSource.Value}'; nothing sent. " +
                $"Set Messaging:Definitions:{templateName} or Messaging:Definitions:{ITemplateCatalog.DefaultKey}.");
            return;
        }

        var code = string.IsNullOrEmpty(command.EncryptedCode)
            ? null
            : decryptor.Decrypt(command.EncryptedCode);

        await email.SendAsync(
            new EmailRequest(
                ContactKey: recipient,
                TemplateKey: templateKey,
                RecipientEmail: recipient,
                Attributes: BuildAttributes(command, recipient, code)),
            ct);

        // The code itself is never recorded.
        audit.Record("CognitoEmailSent", new Dictionary<string, object?>
        {
            ["triggerSource"] = command.TriggerSource.Value,
            ["templateKey"] = templateKey,
            ["recipient"] = Mask(recipient),
        });
    }

    /// <summary>
    /// Keeps the first and last character of the local part, so two addresses that differ
    /// only near the end still read differently in a log line. On an attribute-update
    /// trigger this is what shows whether Cognito targeted the new address or the old one.
    /// </summary>
    private static string Mask(string address)
    {
        var at = address.IndexOf('@');
        if (at <= 0)
        {
            return "***";
        }

        var local = address[..at];
        var domain = address[at..];

        return local.Length < 3
            ? $"{local[0]}***{domain}"
            : $"{local[0]}***{local[^1]}{domain}";
    }

    private static Dictionary<string, object?> BuildAttributes(
        CognitoMessageCommand command, string email, string? code)
    {
        string? Attr(string name) =>
            command.UserAttributes.TryGetValue(name, out var v) ? v : null;

        var attributes = new Dictionary<string, object?>
        {
            ["SubscriberKey"] = email,
            ["EmailAddress"] = email,
            ["VerificationCode"] = code,
            ["LanguageCode"] = Attr("custom:language") ?? "en-US",
            ["FirstName"] = Attr("given_name"),
            ["META_COUNTRY_CODE"] = "US",
        };

        // Client-supplied metadata is applied last so a caller can override presentation
        // values (locale, brand) without a code change.
        if (command.ClientMetadata is not null)
        {
            foreach (var (key, value) in command.ClientMetadata)
            {
                attributes[key] = value;
            }
        }

        return attributes;
    }
}
