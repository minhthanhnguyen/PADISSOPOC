using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Microsoft.Extensions.Options;
using Padi.Services.Authentication.Messaging.Http;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.CustomEmailSender;

/// <summary>
/// Cognito CustomEmailSender trigger. Once this is attached, Cognito sends no email
/// itself — every code below reaches the user only if this function succeeds, so a
/// failure here blocks sign-up, sign-in via email OTP, and password reset.
/// Exceptions are therefore allowed to propagate: a visible failure beats a user
/// waiting indefinitely for a code that was never sent.
/// </summary>
public static class Function
{
    private static MessagingClient Messaging => LambdaHost.Resolve<MessagingClient>();
    private static MessagingOptions Options =>
        LambdaHost.Resolve<IOptionsMonitor<MessagingOptions>>().CurrentValue;

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext ctx)
    {
        var triggerSource = evt["triggerSource"]?.GetValue<string>() ?? "";
        var request = evt["request"]?.AsObject();
        var attrs = request?["userAttributes"]?.AsObject();

        var email = attrs?["email"]?.GetValue<string>();
        if (string.IsNullOrEmpty(email))
        {
            ctx.Logger.LogWarning($"{triggerSource}: user has no email attribute; skipping.");
            return evt;
        }

        var definitionName = Templates.DefinitionKeyFor(triggerSource);
        if (definitionName is null ||
            !Options.Definitions.TryGetValue(definitionName, out var definitionKey) ||
            string.IsNullOrWhiteSpace(definitionKey))
        {
            // Unmapped trigger sources are skipped rather than failed — an unconfigured
            // notification should not block the underlying Cognito operation.
            ctx.Logger.LogWarning(
                $"No Messaging:Definitions entry for '{definitionName ?? triggerSource}'; no message sent.");
            return evt;
        }

        var encrypted = request?["code"]?.GetValue<string>();
        var code = string.IsNullOrEmpty(encrypted) ? null : CodeDecryptor.Decrypt(encrypted);

        var clientMetadata = request?["clientMetadata"]?.AsObject()?
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!.ToString());

        await Messaging.SendEmailAsync(new EmailProxyRequest
        {
            // Keyed by email address to match the messaging service's contact model.
            // Note this makes the contact identity move if a user changes their email;
            // Cognito's sub would be stable across that.
            ContactKey = email,
            DefinitionKey = definitionKey,
            RecipientEmail = email,
            Attributes = Templates.AttributesFor(triggerSource, code, email, attrs, clientMetadata),
        });

        // Never log the code itself.
        ctx.Logger.LogInformation(
            $"{{\"event\":\"CognitoEmailSent\",\"triggerSource\":\"{triggerSource}\"," +
            $"\"definitionKey\":\"{definitionKey}\",\"requestId\":\"{ctx.AwsRequestId}\"}}");

        return evt;
    }
}
