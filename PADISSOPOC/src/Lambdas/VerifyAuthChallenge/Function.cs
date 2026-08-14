using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padisso.MagicLink.Shared;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padisso.MagicLink.VerifyAuthChallenge;

/// <summary>
/// Cognito VerifyAuthChallengeResponse trigger. Confirms the caller is VerifyMagicLink
/// by requiring the shared ADMIN_PROOF secret in both clientMetadata and the challenge answer.
/// The real token validation already happened in VerifyMagicLink against DynamoDB.
/// </summary>
public static class Function
{
    public static JsonObject Handler(JsonObject evt, ILambdaContext _)
    {
        var request  = evt["request"]!.AsObject();
        var response = evt["response"]!.AsObject();
        var proof    = request["clientMetadata"]?.AsObject()?["admin_proof"]?.GetValue<string>() ?? "";
        var answer   = request["challengeAnswer"]?.GetValue<string>() ?? "";

        response["answerCorrect"] =
            !string.IsNullOrEmpty(proof) &&
            Crypto.ConstantTimeEquals(proof, Config.AdminProof) &&
            Crypto.ConstantTimeEquals(answer, Config.AdminProof);
        return evt;
    }
}
