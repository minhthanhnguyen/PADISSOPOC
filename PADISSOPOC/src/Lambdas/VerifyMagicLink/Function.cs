using System.Text.Json.Nodes;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Lambda.Core;
using Padi.Services.Authentication.MagicLink.Aws;
using Padi.Services.Authentication.MagicLink.Shared;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.MagicLink.VerifyMagicLink;

/// <summary>
/// Function URL: POST { "token": "abc123..." }
/// Consumes a magic-link token and returns Cognito tokens. The Cognito session never
/// reaches the client, so its 3-minute lifetime does not constrain the magic link.
/// </summary>
public static class Function
{
    public static async Task<JsonObject> Handler(JsonObject req, ILambdaContext ctx)
    {
        try
        {
            var token = Http.ParseBody(req)?["token"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(token))
            {
                return Http.BadRequest("token required");
            }

            var hash = Crypto.Sha256Hex(token);

            // Atomic single-use consume: conditional delete returns the row only if it existed.
            Dictionary<string, AttributeValue> row;
            try
            {
                var del = await Clients.Ddb.DeleteItemAsync(new DeleteItemRequest
                {
                    TableName           = Config.Table,
                    Key                 = new Dictionary<string, AttributeValue> { ["tokenHash"] = new(hash) },
                    ConditionExpression = "attribute_exists(tokenHash)",
                    ReturnValues        = ReturnValue.ALL_OLD,
                });
                row = del.Attributes;
            }
            catch (ConditionalCheckFailedException)
            {
                return Http.Unauthorized();
            }

            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= long.Parse(row["expiresAt"].N))
            {
                return Http.Unauthorized();
            }

            var username = row["username"].S;
            var metadata = new Dictionary<string, string> { ["admin_proof"] = Config.AdminProof };

            var init = await Clients.Cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
            {
                UserPoolId     = Config.UserPoolId,
                ClientId       = Config.ClientId,
                AuthFlow       = AuthFlowType.CUSTOM_AUTH,
                AuthParameters = new Dictionary<string, string> { ["USERNAME"] = username },
                ClientMetadata = metadata,
            });

            var resp = await Clients.Cognito.AdminRespondToAuthChallengeAsync(new AdminRespondToAuthChallengeRequest
            {
                UserPoolId    = Config.UserPoolId,
                ClientId      = Config.ClientId,
                ChallengeName = ChallengeNameType.CUSTOM_CHALLENGE,
                Session       = init.Session,
                ChallengeResponses = new Dictionary<string, string>
                {
                    ["USERNAME"] = username,
                    ["ANSWER"]   = Config.AdminProof,
                },
                ClientMetadata = metadata,
            });

            var r = resp.AuthenticationResult;
            return Http.Ok(new
            {
                idToken      = r.IdToken,
                accessToken  = r.AccessToken,
                refreshToken = r.RefreshToken,
                expiresIn    = r.ExpiresIn,
                tokenType    = r.TokenType,
            });
        }
        catch (Exception ex)
        {
            ctx.Logger.LogError(ex.ToString());
            return Http.ServerError();
        }
    }
}
