using Microsoft.Extensions.Configuration;

namespace Padi.Services.Authentication.Infrastructure.Configuration;

/// <summary>
/// Adds SSM Parameter Store as a configuration source. The path prefix is stripped, so
/// <c>/padi/services/authentication/Messaging/ClientId</c> becomes the configuration key
/// <c>Messaging:ClientId</c> — indistinguishable from an environment variable to callers.
/// </summary>
public static class ParameterStoreConfiguration
{
    /// <summary>
    /// No-op when CONFIG_PARAMETER_PATH is unset, so a function can share a composition
    /// root without being forced to read parameters.
    /// </summary>
    public static IConfigurationBuilder AddParameterStore(this IConfigurationBuilder builder)
    {
        var path = Environment.GetEnvironmentVariable("CONFIG_PARAMETER_PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return builder;
        }

        return builder.AddSystemsManager(source =>
        {
            source.Path = path;
            source.Optional = false;
            // Best-effort refresh. Lambda freezes the execution environment between
            // invocations, so this timer fires only while the sandbox is thawed — a
            // rotated parameter is reliably picked up on the next cold start, not
            // necessarily within this interval.
            source.ReloadAfter = TimeSpan.FromMinutes(15);
        });
    }
}
