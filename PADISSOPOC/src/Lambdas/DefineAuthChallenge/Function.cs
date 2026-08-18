using System.Text.Json.Nodes;
using Amazon.Lambda.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.MagicLink.DefineAuthChallenge;

/// <summary>
/// Cognito DefineAuthChallenge trigger. Decides which challenge to issue next.
/// Only ever invoked via VerifyMagicLink's server-side AdminInitiateAuth call.
/// </summary>
public static class Function
{
    public static JsonObject Handler(JsonObject evt, ILambdaContext _)
    {
        var request  = evt["request"]!.AsObject();
        var response = evt["response"]!.AsObject();
        var session  = request["session"]!.AsArray();

        if (session.Count == 0)
        {
            response["issueTokens"]        = false;
            response["failAuthentication"] = false;
            response["challengeName"]      = "CUSTOM_CHALLENGE";
        }
        else
        {
            var last = session[^1]!.AsObject();
            var ok   = last["challengeResult"]?.GetValue<bool>() ?? false;
            response["issueTokens"]        = ok;
            response["failAuthentication"] = !ok;
        }
        return evt;
    }
}
