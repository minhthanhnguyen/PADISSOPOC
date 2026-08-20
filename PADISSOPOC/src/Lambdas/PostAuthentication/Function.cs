using System.Text.Json.Nodes;
using Amazon.CognitoIdentityProvider;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;
using Padi.Services.Authentication.Infrastructure.Cognito;
using Padi.Services.Authentication.Infrastructure.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.PostAuthentication;

/// <summary>
/// Cognito PostAuthentication trigger. Runs inside the sign-in path, so it must never
/// throw — the use case isolates each step internally and this adapter adds a final guard.
/// </summary>
public static class Function
{
    private static readonly Lazy<RecordSignIn> UseCase = new(() => new RecordSignIn(
        new CognitoUserDirectory(new AmazonCognitoIdentityProviderClient()),
        new ConsoleAuditLog(),
        new SystemClock()));

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext ctx)
    {
        try
        {
            var request = evt["request"]?.AsObject();

            await UseCase.Value.ExecuteAsync(new SignInCommand(
                UserPoolId: evt["userPoolId"]?.GetValue<string>() ?? "",
                Username: evt["userName"]?.GetValue<string>() ?? "",
                TriggerSource: evt["triggerSource"]?.GetValue<string>() ?? "",
                ClientId: evt["callerContext"]?["clientId"]?.GetValue<string>(),
                NewDeviceUsed: request?["newDeviceUsed"]?.GetValue<bool>(),
                UserAttributes: ReadAttributes(request)));
        }
        catch (Exception ex)
        {
            // A failure here would block an already-successful authentication.
            ctx.Logger.LogError($"post-authentication trigger failed: {ex}");
        }

        return evt;
    }

    internal static Dictionary<string, string> ReadAttributes(JsonObject? request) =>
        request?["userAttributes"]?.AsObject()
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!.ToString())
        ?? [];
}
