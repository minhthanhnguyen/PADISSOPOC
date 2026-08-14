using Amazon.CognitoIdentityProvider;
using Amazon.DynamoDBv2;
using Amazon.SimpleEmailV2;
using Amazon.SimpleNotificationService;

namespace Padisso.MagicLink.Aws;

/// <summary>
/// Lazily-initialised AWS clients, reused across warm invocations. Lazy rather than
/// eager so a function only pays construction cost for the services it actually calls.
/// </summary>
public static class Clients
{
    private static readonly Lazy<AmazonDynamoDBClient> _ddb = new(() => new AmazonDynamoDBClient());
    private static readonly Lazy<AmazonSimpleEmailServiceV2Client> _ses = new(() => new AmazonSimpleEmailServiceV2Client());
    private static readonly Lazy<AmazonSimpleNotificationServiceClient> _sns = new(() => new AmazonSimpleNotificationServiceClient());
    private static readonly Lazy<AmazonCognitoIdentityProviderClient> _cognito = new(() => new AmazonCognitoIdentityProviderClient());

    public static AmazonDynamoDBClient Ddb => _ddb.Value;
    public static AmazonSimpleEmailServiceV2Client Ses => _ses.Value;
    public static AmazonSimpleNotificationServiceClient Sns => _sns.Value;
    public static AmazonCognitoIdentityProviderClient Cognito => _cognito.Value;
}
