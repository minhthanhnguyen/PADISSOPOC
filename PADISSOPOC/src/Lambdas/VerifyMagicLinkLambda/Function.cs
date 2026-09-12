using System.Text.Json;
using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.MagicLink;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.MagicLink.VerifyMagicLink;

/// <summary>
/// Function URL: POST { "token": "…" }
///
/// Returns Cognito tokens directly rather than establishing a session, so the caller
/// persists them itself.
/// </summary>
public static class Function
{
    public static async Task<JsonObject> Handler(JsonObject req, ILambdaContext ctx)
    {
        try
        {
            var token = ParseBody(req)?["token"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(token))
            {
                return Response(400, new { error = "token required" });
            }

            var result = await Composition.Resolve<RedeemMagicLink>().ExecuteAsync(token);
            if (!result.Succeeded || result.Tokens is null)
            {
                return Response(401, new { error = "invalid or expired token" });
            }

            var tokens = result.Tokens;
            return Response(200, new
            {
                idToken = tokens.IdToken,
                accessToken = tokens.AccessToken,
                refreshToken = tokens.RefreshToken,
                expiresIn = tokens.ExpiresIn,
                tokenType = tokens.TokenType,
            });
        }
        catch (Exception ex)
        {
            ctx.Logger.LogError(ex.ToString());
            return Response(500, new { error = "internal error" });
        }
    }

    private static JsonObject? ParseBody(JsonObject req)
    {
        var raw = req["body"]?.GetValue<string>();
        return string.IsNullOrEmpty(raw) ? null : JsonNode.Parse(raw)?.AsObject();
    }

    private static JsonObject Response(int status, object body) => new()
    {
        ["statusCode"] = status,
        ["headers"] = new JsonObject { ["content-type"] = "application/json" },
        ["body"] = JsonSerializer.Serialize(body),
    };
}
