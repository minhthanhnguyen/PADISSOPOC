using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
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
    // Resolved from the container built once per execution environment. Configuration
    // behind it comes from SSM Parameter Store and environment variables alike.
    private static MessagingClient Messaging => LambdaHost.Resolve<MessagingClient>();

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext ctx)
    {
        var triggerSource = evt["triggerSource"]?.GetValue<string>() ?? "";
        var request = evt["request"]?.AsObject();
        var attrs = request?["userAttributes"]?.AsObject();

        var email = attrs?["email"]?.GetValue<string>();
        if (string.IsNullOrEmpty(email))
        {
            // Nothing to deliver to. Log and return rather than fail the whole operation.
            ctx.Logger.LogWarning($"{triggerSource}: user has no email attribute; skipping.");
            return evt;
        }

        var encrypted = request?["code"]?.GetValue<string>();
        var code = string.IsNullOrEmpty(encrypted) ? null : CodeDecryptor.Decrypt(encrypted);

        var template = Templates.For(triggerSource, code, attrs);
        if (template is null)
        {
            ctx.Logger.LogWarning($"Unhandled triggerSource '{triggerSource}'; no message sent.");
            return evt;
        }

        var metadata = request?["clientMetadata"]?.AsObject()?
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!.ToString());

        await Messaging.SendEmailAsync(new EmailMessage
        {
            To = email,
            Subject = template.Subject,
            HtmlBody = template.Html,
            TextBody = template.Text,
            Metadata = metadata,
        });

        // Never log the code itself.
        ctx.Logger.LogInformation(
            $"{{\"event\":\"CognitoEmailSent\",\"triggerSource\":\"{triggerSource}\",\"requestId\":\"{ctx.AwsRequestId}\"}}");

        return evt;
    }
}
