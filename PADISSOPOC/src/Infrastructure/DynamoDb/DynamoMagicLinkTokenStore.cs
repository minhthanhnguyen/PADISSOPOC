using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.MagicLink;

namespace Padi.Services.Authentication.Infrastructure.DynamoDb;

/// <summary>
/// Stores only the SHA-256 hash of each token, keyed by that hash. DynamoDB TTL sweeps
/// expired rows, but expiry is still checked on read — TTL deletion is best-effort and
/// can lag by hours.
/// </summary>
public sealed class DynamoMagicLinkTokenStore(IAmazonDynamoDB dynamo, string tableName) : IMagicLinkTokenStore
{
    public Task SaveAsync(MagicLinkToken token, CancellationToken ct = default) =>
        dynamo.PutItemAsync(new PutItemRequest
        {
            TableName = tableName,
            Item = new Dictionary<string, AttributeValue>
            {
                ["tokenHash"] = new(token.Hash),
                ["username"] = new(token.Username),
                ["channel"] = new(token.Channel.ToString()),
                ["expiresAt"] = new() { N = token.ExpiresAt.ToUnixTimeSeconds().ToString() },
            },
        }, ct);

    public async Task<StoredMagicLink?> ConsumeAsync(string tokenHash, CancellationToken ct = default)
    {
        try
        {
            // Conditional delete returning ALL_OLD makes consumption atomic: two concurrent
            // redemptions cannot both observe the row.
            var deleted = await dynamo.DeleteItemAsync(new DeleteItemRequest
            {
                TableName = tableName,
                Key = new Dictionary<string, AttributeValue> { ["tokenHash"] = new(tokenHash) },
                ConditionExpression = "attribute_exists(tokenHash)",
                ReturnValues = ReturnValue.ALL_OLD,
            }, ct);

            return new StoredMagicLink(
                deleted.Attributes["username"].S,
                DateTimeOffset.FromUnixTimeSeconds(long.Parse(deleted.Attributes["expiresAt"].N)));
        }
        catch (ConditionalCheckFailedException)
        {
            return null;
        }
    }
}
