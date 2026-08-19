using System.Text.Json.Nodes;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.DynamoDBv2.Model;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.MagicLink.Aws;
using Padi.Services.Authentication.MagicLink.Shared;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.MagicLink.RequestMagicLink;

/// <summary>
/// Function URL: POST { "username": "alice", "channel": "email" | "sms" }
/// Generates a magic-link token, stores its hash in DynamoDB, and delivers the link
/// over the requested channel. "channel" is optional and defaults to email.
/// Always returns 200 so the endpoint cannot be used for user enumeration.
/// </summary>
public static class Function
{
    public static async Task<JsonObject> Handler(JsonObject req, ILambdaContext ctx)
    {
        try
        {
            var body     = Http.ParseBody(req);
            var username = body?["username"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(username))
            {
                return Http.BadRequest("username required");
            }

            // An unsupported channel is a caller error, not a missing user — safe to surface.
            var channelName = body?["channel"]?.GetValue<string>();
            var channel = ChannelResolver.Resolve(channelName);
            if (channel is null)
            {
                return Http.BadRequest("channel must be 'email' or 'sms'");
            }

            try
            {
                var user = await Clients.Cognito.AdminGetUserAsync(new AdminGetUserRequest
                {
                    UserPoolId = Config.UserPoolId,
                    Username   = username,
                });

                var destination = user.UserAttributes
                    .FirstOrDefault(a => a.Name == channel.UserAttribute)?.Value;

                if (!string.IsNullOrEmpty(destination))
                {
                    var token     = Crypto.GenerateToken();
                    var expiresAt = DateTimeOffset.UtcNow.AddMinutes(Config.TtlMin).ToUnixTimeSeconds();

                    await Clients.Ddb.PutItemAsync(new PutItemRequest
                    {
                        TableName = Config.Table,
                        Item = new Dictionary<string, AttributeValue>
                        {
                            ["tokenHash"] = new(Crypto.Sha256Hex(token)),
                            ["username"]  = new(username),
                            ["channel"]   = new(channel.Channel.ToString()),
                            ["expiresAt"] = new() { N = expiresAt.ToString() },
                        },
                    });

                    await channel.SendAsync(destination, token);
                }
            }
            catch (UserNotFoundException)
            {
                // Deliberately silent — never reveal whether the account exists.
            }

            return Http.Ok(new { ok = true });
        }
        catch (Exception ex)
        {
            ctx.Logger.LogError(ex.ToString());
            return Http.ServerError();
        }
    }
}
