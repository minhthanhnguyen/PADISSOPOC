using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Padi.Services.Authentication.Messaging.Http;

/// <summary>
/// Builds configuration and the DI container once per Lambda execution environment.
///
/// Configuration sources, in precedence order (later wins):
///   1. SSM Parameter Store under CONFIG_PARAMETER_PATH — secrets and template ids
///   2. Environment variables — non-secret settings, e.g. Messaging__EmailUrl
///
/// Because SSM parameters surface as ordinary configuration keys, callers read them
/// through <see cref="IConfiguration"/> exactly like environment variables.
///
/// Note the ordering: an environment variable SHADOWS an SSM parameter of the same key.
/// That is intentional so a value can be pinned per function, but it means anything
/// sourced from Parameter Store must not also be set as an environment variable —
/// template ids under Messaging:Definitions are a case in point.
/// </summary>
public static class LambdaHost
{
    private static readonly Lazy<IServiceProvider> Lazy = new(Build, LazyThreadSafetyMode.ExecutionAndPublication);

    public static IServiceProvider Services => Lazy.Value;

    public static IConfiguration Configuration => Services.GetRequiredService<IConfiguration>();

    public static T Resolve<T>() where T : notnull => Services.GetRequiredService<T>();

    private static IServiceProvider Build()
    {
        var parameterPath = Environment.GetEnvironmentVariable("CONFIG_PARAMETER_PATH");

        var builder = new ConfigurationBuilder();

        if (!string.IsNullOrWhiteSpace(parameterPath))
        {
            builder.AddSystemsManager(source =>
            {
                source.Path = parameterPath;
                source.Optional = false;
                // Picks up rotated parameters without a redeploy. The provider refreshes
                // in the background, so this does not sit in the request path.
                source.ReloadAfter = TimeSpan.FromMinutes(15);
            });
        }

        // Environment variables last so non-secret settings can override, and so a local
        // run can supply everything without touching SSM.
        builder.AddEnvironmentVariables();

        var configuration = builder.Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);

        // Validation runs lazily on first resolve. There is no IHost here to trigger
        // ValidateOnStart, and failing on first use gives a clearer Lambda error anyway.
        services.AddOptions<MessagingOptions>()
            .Bind(configuration.GetSection(MessagingOptions.SectionName))
            .ValidateDataAnnotations();

        services.AddHttpClient<BearerTokenProvider>(c => c.Timeout = TimeSpan.FromSeconds(8));
        services.AddHttpClient<MessagingClient>(c => c.Timeout = TimeSpan.FromSeconds(8));

        return services.BuildServiceProvider();
    }
}
