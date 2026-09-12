using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.CreateAuthChallenge;

/// <summary>
/// Cognito CreateAuthChallenge trigger. Required by Cognito whenever DefineAuthChallenge
/// issues a CUSTOM_CHALLENGE, but there is nothing to create — the magic-link token was
/// validated before this exchange began.
/// </summary>
public static class Function
{
    public static JsonObject Handler(JsonObject evt, ILambdaContext _)
    {
        var response = evt["response"]!.AsObject();
        response["publicChallengeParameters"] = new JsonObject();

        var privateParameters = new JsonObject();
        foreach (var (key, value) in CustomAuthChallenge.CreatePrivateParameters())
        {
            privateParameters[key] = value;
        }

        response["privateChallengeParameters"] = privateParameters;
        response["challengeMetadata"] = "MAGIC_LINK";
        return evt;
    }
}
