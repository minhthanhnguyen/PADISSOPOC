using System.Text.Json.Nodes;
using Amazon.Lambda.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.MagicLink.CreateAuthChallenge;

/// <summary>
/// Cognito CreateAuthChallenge trigger. Rubber stamp — the magic-link email is sent
/// by RequestMagicLink, and the token is already validated by VerifyMagicLink before
/// this challenge is ever created.
/// </summary>
public static class Function
{
    public static JsonObject Handler(JsonObject evt, ILambdaContext _)
    {
        var response = evt["response"]!.AsObject();
        response["publicChallengeParameters"]  = new JsonObject();
        response["privateChallengeParameters"] = new JsonObject { ["expected"] = "MAGIC" };
        response["challengeMetadata"]          = "MAGIC_LINK";
        return evt;
    }
}
