using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.VerifyAuthChallenge;

/// <summary>
/// Cognito VerifyAuthChallengeResponse trigger. Confirms the exchange was started by the
/// one component permitted to call AdminInitiateAuth; the user's own credential — the
/// magic-link token — was already checked against the store before this point.
/// </summary>
public static class Function
{
    private static readonly string AdminProof =
        Environment.GetEnvironmentVariable("ADMIN_PROOF")
        ?? throw new InvalidOperationException("Missing required environment variable: ADMIN_PROOF");

    public static JsonObject Handler(JsonObject evt, ILambdaContext _)
    {
        var request = evt["request"]!.AsObject();
        var proof = request["clientMetadata"]?.AsObject()?["admin_proof"]?.GetValue<string>();
        var answer = request["challengeAnswer"]?.GetValue<string>();

        evt["response"]!.AsObject()["answerCorrect"] =
            CustomAuthChallenge.Verify(proof, answer, AdminProof);

        return evt;
    }
}
