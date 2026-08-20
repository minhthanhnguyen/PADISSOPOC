using Microsoft.Extensions.Configuration;

namespace Padi.Services.Authentication.Infrastructure.Core;

/// <summary>
/// Configuration for a Lambda execution environment, from environment variables.
///
/// Functions that also read SSM Parameter Store call <c>AddParameterStore()</c> from
/// Infrastructure.Configuration before <see cref="AddEnvironment"/>. Environment
/// variables are applied last and therefore win on a key collision — intentional, so a
/// value can be pinned per function, but it means anything sourced from Parameter Store
/// must not also be set in the environment.
/// </summary>
public static class LambdaConfiguration
{
    public static ConfigurationBuilder Create() => new();

    public static IConfigurationBuilder AddEnvironment(this IConfigurationBuilder builder) =>
        builder.AddEnvironmentVariables();

    /// <summary>Environment-only configuration, for functions that read no parameters.</summary>
    public static IConfigurationRoot FromEnvironment() => Create().AddEnvironment().Build();

    public static string Require(this IConfiguration configuration, string key) =>
        configuration[key] ?? throw new InvalidOperationException($"Missing required configuration value: {key}");
}
