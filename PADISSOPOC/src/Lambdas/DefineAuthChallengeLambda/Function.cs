using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.Cognito;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.DefineAuthChallenge;

/// <summary>
/// Cognito DefineAuthChallenge trigger. A thin adapter: translates the event into the
/// shape the use case expects and writes the decision back. All logic lives in
/// <see cref="CustomAuthChallenge"/>, which has no AWS dependencies.
/// </summary>
public static class Function
{
    public static JsonObject Handler(JsonObject evt, ILambdaContext _)
    {
        var session = evt["request"]?["session"]?.AsArray() ?? [];
        var priorResults = session
            .Select(entry => entry?["challengeResult"]?.GetValue<bool>() ?? false)
            .ToList();

        var decision = CustomAuthChallenge.Define(priorResults);

        var response = evt["response"]!.AsObject();
        response["issueTokens"] = decision.IssueTokens;
        response["failAuthentication"] = decision.FailAuthentication;
        if (decision.ChallengeName is not null)
        {
            response["challengeName"] = decision.ChallengeName;
        }

        return evt;
    }
}
