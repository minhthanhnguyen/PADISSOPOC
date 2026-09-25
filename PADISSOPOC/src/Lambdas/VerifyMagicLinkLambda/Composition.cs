using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.DynamoDBv2;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.MagicLink;
using Padi.Services.Authentication.Infrastructure.Cognito;
using Padi.Services.Authentication.Infrastructure.Core;
using Padi.Services.Authentication.Infrastructure.DynamoDb;

namespace Padi.Services.Authentication.MagicLink.VerifyMagicLink;

internal static class Composition
{
    private static readonly Lazy<IServiceProvider> Provider = new(Build, LazyThreadSafetyMode.ExecutionAndPublication);

    public static T Resolve<T>() where T : notnull => Provider.Value.GetRequiredService<T>();

    private static IServiceProvider Build()
    {
        var configuration = LambdaConfiguration.FromEnvironment();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton<IClock, SystemClock>();

        services.AddSingleton<IMagicLinkTokenStore>(
            _ => new DynamoMagicLinkTokenStore(new AmazonDynamoDBClient(), configuration.Require("MAGIC_LINK_TABLE")));

        services.AddSingleton<IAuthenticator>(_ =>
        {
            var cognito = new AmazonCognitoIdentityProviderClient();
            var userPoolId = configuration.Require("USER_POOL_ID");
            var clientId = configuration.Require("MAGIC_LINK_CLIENT_ID");

            // Both secrets are fetched at cold start rather than passed as environment
            // variables, which lambda:GetFunctionConfiguration returns in plain text. Holding
            // them is what lets a caller sign in as any user, so they must not be readable by
            // anyone with read-only access to the function.
            var clientSecret = cognito.DescribeUserPoolClientAsync(new DescribeUserPoolClientRequest
            {
                UserPoolId = userPoolId,
                ClientId = clientId,
            }).GetAwaiter().GetResult().UserPoolClient.ClientSecret;

            using var secrets = new AmazonSecretsManagerClient();
            var adminProof = secrets.GetSecretValueAsync(new GetSecretValueRequest
            {
                SecretId = configuration.Require("ADMIN_PROOF_SECRET_ID"),
            }).GetAwaiter().GetResult().SecretString;

            return new CognitoCustomAuthenticator(cognito, new CognitoAuthOptions
            {
                UserPoolId = userPoolId,
                ClientId = clientId,
                ClientSecret = clientSecret,
                AdminProof = adminProof,
            });
        });

        services.AddSingleton<RedeemMagicLink>();

        return services.BuildServiceProvider();
    }
}
