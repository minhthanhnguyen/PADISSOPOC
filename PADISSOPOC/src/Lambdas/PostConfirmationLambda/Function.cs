using System.Text.Json.Nodes;
using Amazon.CognitoIdentityProvider;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;
using Padi.Services.Authentication.Infrastructure.Cognito;
using Padi.Services.Authentication.Infrastructure.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.PostConfirmation;

/// <summary>
/// Cognito PostConfirmation trigger. Assigns the sign-in alias chosen at sign-up.
///
/// Exceptions propagate deliberately, unlike the PostAuthentication trigger. This runs
/// after confirmation rather than inside a sign-in, and an account with no
/// <c>preferred_username</c> is unreachable — the user only knows the name they typed, not
/// the UUID behind it. A visible failure beats a silently broken account.
/// </summary>
public static class Function
{
    private static readonly Lazy<AssignPreferredUsername> UseCase = new(() => new AssignPreferredUsername(
        new CognitoUserDirectory(new AmazonCognitoIdentityProviderClient()),
        new ConsoleAuditLog()));

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext _)
    {
        var request = evt["request"]?.AsObject();

        await UseCase.Value.ExecuteAsync(new AssignPreferredUsernameCommand(
            UserPoolId: evt["userPoolId"]?.GetValue<string>() ?? "",
            Username: evt["userName"]?.GetValue<string>() ?? "",
            UserAttributes: ReadAttributes(request)));

        return evt;
    }

    private static Dictionary<string, string> ReadAttributes(JsonObject? request) =>
        request?["userAttributes"]?.AsObject()
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!.ToString())
        ?? [];
}
