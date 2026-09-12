using Amazon.CognitoIdentityProvider;
using Amazon.DynamoDBv2;
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

        services.AddSingleton<IAuthenticator>(_ => new CognitoCustomAuthenticator(
            new AmazonCognitoIdentityProviderClient(),
            new CognitoAuthOptions
            {
                UserPoolId = configuration.Require("USER_POOL_ID"),
                ClientId = configuration.Require("CLIENT_ID"),
                AdminProof = configuration.Require("ADMIN_PROOF"),
            }));

        services.AddSingleton<RedeemMagicLink>();

        return services.BuildServiceProvider();
    }
}
