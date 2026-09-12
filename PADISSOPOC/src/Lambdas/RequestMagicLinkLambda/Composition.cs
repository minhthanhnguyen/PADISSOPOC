using Amazon.CognitoIdentityProvider;
using Amazon.DynamoDBv2;
using Amazon.SimpleEmailV2;
using Amazon.SimpleNotificationService;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.MagicLink;
using Padi.Services.Authentication.Infrastructure.Cognito;
using Padi.Services.Authentication.Infrastructure.Core;
using Padi.Services.Authentication.Infrastructure.DynamoDb;
using Padi.Services.Authentication.Infrastructure.Notifications;

namespace Padi.Services.Authentication.MagicLink.RequestMagicLink;

internal static class Composition
{
    private static readonly Lazy<IServiceProvider> Provider = new(Build, LazyThreadSafetyMode.ExecutionAndPublication);

    public static T Resolve<T>() where T : notnull => Provider.Value.GetRequiredService<T>();
    public static string UserPoolId => Provider.Value.GetRequiredService<IConfiguration>().Require("USER_POOL_ID");

    private static IServiceProvider Build()
    {
        var configuration = LambdaConfiguration.FromEnvironment();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<IAuditLog, ConsoleAuditLog>();

        services.AddSingleton<IUserDirectory>(
            _ => new CognitoUserDirectory(new AmazonCognitoIdentityProviderClient()));
        services.AddSingleton<IMagicLinkTokenStore>(
            _ => new DynamoMagicLinkTokenStore(new AmazonDynamoDBClient(), configuration.Require("MAGIC_LINK_TABLE")));

        var delivery = new MagicLinkDeliveryOptions
        {
            BaseUrl = configuration.Require("MAGIC_LINK_BASE_URL"),
            FromAddress = configuration.Require("MAGIC_LINK_EMAIL_FROM"),
            SmsSenderId = configuration["MAGIC_LINK_SMS_SENDER_ID"],
            Lifetime = Application.MagicLink.RequestMagicLink.Lifetime,
        };
        services.AddSingleton(delivery);
        services.AddSingleton<IMagicLinkDelivery>(
            _ => new SesMagicLinkDelivery(new AmazonSimpleEmailServiceV2Client(), delivery));
        services.AddSingleton<IMagicLinkDelivery>(
            _ => new SnsMagicLinkDelivery(new AmazonSimpleNotificationServiceClient(), delivery));

        services.AddSingleton<Application.MagicLink.RequestMagicLink>();

        return services.BuildServiceProvider();
    }
}
