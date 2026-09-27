using System.Text.Json.Nodes;
using Amazon.CognitoIdentityProvider;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;
using Padi.Services.Authentication.Infrastructure.Cognito;
using Padi.Services.Authentication.Infrastructure.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.PreSignUp;

/// <summary>
/// Cognito PreSignUp trigger. Applies the API's sign-up rules to every self sign-up, including
/// direct calls to Cognito that never touch the API.
///
/// A rejection propagates as an exception, which is how a PreSignUp trigger refuses a
/// sign-up: Cognito creates nothing and returns UserLambdaValidationException carrying the
/// message.
/// </summary>
public static class Function
{
    private static readonly Lazy<CheckSelfSignUp> UseCase = new(() => new CheckSelfSignUp(
        new CognitoUsernameAvailability(new AmazonCognitoIdentityProviderClient()),
        new ConsoleAuditLog()));

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext _)
    {
        if (evt["triggerSource"]?.GetValue<string>() != CheckSelfSignUp.SelfSignUpTrigger)
        {
            return evt;
        }

        await UseCase.Value.ExecuteAsync(new SelfSignUpCheck(
            UserPoolId: evt["userPoolId"]?.GetValue<string>() ?? "",
            Username: evt["userName"]?.GetValue<string>() ?? "",
            UserAttributes: ReadAttributes(evt["request"]?["userAttributes"]?.AsObject())));

        return evt;
    }

    private static Dictionary<string, string> ReadAttributes(JsonObject? attributes) =>
        attributes?
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!.ToString())
        ?? [];
}
