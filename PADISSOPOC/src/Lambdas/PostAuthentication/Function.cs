using System.Text.Json;
using System.Text.Json.Nodes;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Lambda.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padisso.Cognito.PostAuthentication;

/// <summary>
/// Cognito PostAuthentication trigger. Emits a structured audit record and stamps
/// custom:last_login on the user.
///
/// Runs synchronously inside the sign-in path, so it must never throw — an unhandled
/// exception here fails the user's authentication. Every failure is caught and logged.
/// </summary>
public static class Function
{
    private static readonly Lazy<AmazonCognitoIdentityProviderClient> _cognito =
        new(() => new AmazonCognitoIdentityProviderClient());

    private const string LastLoginAttribute = "custom:last_login";

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext ctx)
    {
        var signedInAt = DateTimeOffset.UtcNow;

        // Audit first: a failure writing the attribute must not lose the audit record.
        try
        {
            WriteAuditRecord(evt, signedInAt, ctx);
        }
        catch (Exception ex)
        {
            ctx.Logger.LogError($"post-auth audit logging failed: {ex}");
        }

        try
        {
            await StampLastLogin(evt, signedInAt);
        }
        catch (Exception ex)
        {
            // Non-fatal: the user is already authenticated and a stale last_login
            // is not worth blocking a sign-in over.
            ctx.Logger.LogError($"post-auth last_login update failed: {ex}");
        }

        return evt;
    }

    /// <summary>Single-line JSON so CloudWatch Logs Insights can query the fields directly.</summary>
    private static void WriteAuditRecord(JsonObject evt, DateTimeOffset at, ILambdaContext ctx)
    {
        var request = evt["request"]?.AsObject();
        var attrs   = request?["userAttributes"]?.AsObject();

        var record = new
        {
            eventType     = "SignIn",
            timestamp     = at.ToString("O"),
            userPoolId    = evt["userPoolId"]?.GetValue<string>(),
            userName      = evt["userName"]?.GetValue<string>(),
            triggerSource = evt["triggerSource"]?.GetValue<string>(),
            clientId      = evt["callerContext"]?["clientId"]?.GetValue<string>(),
            sub           = Attr(attrs, "sub"),
            email         = Attr(attrs, "email"),
            identities    = Attr(attrs, "identities"),   // present for federated sign-ins
            padiId        = Attr(attrs, "custom:padi_id"),
            newDeviceUsed = request?["newDeviceUsed"]?.GetValue<bool>(),
            requestId     = ctx.AwsRequestId,
        };

        ctx.Logger.LogInformation(JsonSerializer.Serialize(record));
    }

    private static async Task StampLastLogin(JsonObject evt, DateTimeOffset at)
    {
        var userPoolId = evt["userPoolId"]?.GetValue<string>();
        var userName   = evt["userName"]?.GetValue<string>();
        if (string.IsNullOrEmpty(userPoolId) || string.IsNullOrEmpty(userName)) return;

        await _cognito.Value.AdminUpdateUserAttributesAsync(new AdminUpdateUserAttributesRequest
        {
            UserPoolId = userPoolId,
            Username   = userName,
            UserAttributes = new List<AttributeType>
            {
                new() { Name = LastLoginAttribute, Value = at.ToString("O") },
            },
        });
    }

    private static string? Attr(JsonObject? attrs, string name) =>
        attrs?[name]?.GetValue<string>();
}
