using System.Text.Json;
using System.Text.Json.Nodes;

namespace Padisso.MagicLink.Shared;

/// <summary>Lambda Function URL request/response helpers.</summary>
public static class Http
{
    public static JsonObject? ParseBody(JsonObject req)
    {
        var raw = req["body"]?.GetValue<string>();
        return string.IsNullOrEmpty(raw) ? null : JsonNode.Parse(raw)?.AsObject();
    }

    public static JsonObject Ok(object body)          => Response(200, body);
    public static JsonObject BadRequest(string msg)   => Response(400, new { error = msg });
    public static JsonObject Unauthorized()           => Response(401, new { error = "invalid or expired token" });
    public static JsonObject ServerError()            => Response(500, new { error = "internal error" });

    public static JsonObject Response(int status, object body) => new()
    {
        ["statusCode"] = status,
        ["headers"]    = new JsonObject { ["content-type"] = "application/json" },
        ["body"]       = JsonSerializer.Serialize(body),
    };
}
