using System.Text.Json;
using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.Application.MagicLink;
using Padi.Services.Authentication.Domain.MagicLink;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.MagicLink.RequestMagicLink;

/// <summary>
/// Function URL: POST { "username": "alice", "channel": "email" | "sms" }
///
/// Always returns 200 for a well-formed request, whether or not the account exists —
/// the endpoint must not become a user-enumeration oracle. An unsupported channel is a
/// caller error and safe to report.
/// </summary>
public static class Function
{
    public static async Task<JsonObject> Handler(JsonObject req, ILambdaContext ctx)
    {
        try
        {
            var body = ParseBody(req);

            var username = body?["username"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(username))
            {
                return Response(400, new { error = "username required" });
            }

            var channel = DeliveryChannelExtensions.Parse(body?["channel"]?.GetValue<string>());
            if (channel is null)
            {
                return Response(400, new { error = "channel must be 'email' or 'sms'" });
            }

            await Composition.Resolve<Application.MagicLink.RequestMagicLink>()
                .ExecuteAsync(new RequestMagicLinkCommand(Composition.UserPoolId, username, channel.Value));

            return Response(200, new { ok = true });
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
