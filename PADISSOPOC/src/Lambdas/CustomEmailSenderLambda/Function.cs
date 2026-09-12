using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;
using Padi.Services.Authentication.Domain.Cognito;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.CustomEmailSender;

/// <summary>
/// Cognito CustomEmailSender trigger. Once attached, Cognito sends no email itself, so a
/// failure here means the user never receives their code. Exceptions are deliberately
/// allowed to propagate: a visible failure beats silent non-delivery.
/// </summary>
public static class Function
{
    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext _)
    {
        var request = evt["request"]?.AsObject();

        await Composition.Resolve<SendCognitoMessage>().ExecuteAsync(new CognitoMessageCommand(
            TriggerSource: new CognitoTriggerSource(evt["triggerSource"]?.GetValue<string>() ?? ""),
            EncryptedCode: request?["code"]?.GetValue<string>(),
            UserAttributes: ReadDictionary(request?["userAttributes"]?.AsObject()),
            ClientMetadata: ReadDictionary(request?["clientMetadata"]?.AsObject())));

        return evt;
    }

    private static Dictionary<string, string> ReadDictionary(JsonObject? source) =>
        source?
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!.ToString())
        ?? [];
}
