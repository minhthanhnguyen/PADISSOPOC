using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.Cognito;
using Padi.Services.Authentication.Infrastructure.Configuration;
using Padi.Services.Authentication.Infrastructure.Core;
using Padi.Services.Authentication.Infrastructure.Kms;
using Padi.Services.Authentication.Infrastructure.Messaging;

namespace Padi.Services.Authentication.Cognito.CustomEmailSender;

/// <summary>Composition root. Built once per execution environment.</summary>
internal static class Composition
{
    private static readonly Lazy<IServiceProvider> Provider = new(Build, LazyThreadSafetyMode.ExecutionAndPublication);

    public static T Resolve<T>() where T : notnull => Provider.Value.GetRequiredService<T>();

    private static IServiceProvider Build()
    {
        var configuration = LambdaConfiguration.Create().AddParameterStore().AddEnvironment().Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);

        // Validated lazily on first resolve — there is no IHost to trigger ValidateOnStart,
        // and failing on first use gives a clearer error in the invocation log.
        services.AddOptions<MessagingOptions>()
            .Bind(configuration.GetSection(MessagingOptions.SectionName))
            .ValidateDataAnnotations();

        services.AddSingleton<IAuditLog, ConsoleAuditLog>();
        services.AddSingleton<ITemplateCatalog, OptionsTemplateCatalog>();
        services.AddSingleton<ICodeDecryptor>(
            _ => new EncryptionSdkCodeDecryptor(configuration.Require("KEY_ARN")));

        services.AddHttpClient<BearerTokenProvider>(c => c.Timeout = TimeSpan.FromSeconds(8));
        services.AddHttpClient<MessagingEmailSender>(c => c.Timeout = TimeSpan.FromSeconds(8));
        services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<MessagingEmailSender>());

        services.AddSingleton<SendCognitoMessage>();

        return services.BuildServiceProvider();
    }
}
