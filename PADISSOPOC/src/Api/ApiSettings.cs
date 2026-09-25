using Padi.Services.Authentication.Infrastructure.Core;

namespace Padi.Services.Authentication.Api;

/// <summary>
/// Startup settings, resolved once and passed explicitly rather than read from
/// <c>IConfiguration</c> at each use. Missing required values fail at startup, where the
/// error is obvious, instead of on the first request that happens to need them.
/// </summary>
public sealed class ApiSettings
{
    private const string DefaultRegion = "us-west-2";
    private const string DefaultAdminGroup = "padi-sso-admins";

    private ApiSettings(
        string region, string userPoolId, string clientId, string adminGroup, string[] allowedOrigins,
        string? basePath)
    {
        Region = region;
        UserPoolId = userPoolId;
        ClientId = clientId;
        AdminGroup = adminGroup;
        AllowedOrigins = allowedOrigins;
        BasePath = basePath;
    }

    public string Region { get; }

    public string UserPoolId { get; }

    public string ClientId { get; }

    public string AdminGroup { get; }

    /// <summary>
    /// Browser origins allowed to call the API.
    ///
    /// API Gateway's CORS configuration only answers the OPTIONS preflight — with a Lambda
    /// proxy integration the actual response carries whatever headers this app sets, so
    /// without CORS here a browser rejects every real response despite a passing preflight.
    /// </summary>
    public string[] AllowedOrigins { get; }

    /// <summary>
    /// The custom domain's base path, e.g. <c>/p/padi-auth-poc</c>, or null when there is none.
    ///
    /// API Gateway forwards requests for a named (non-greedy) resource with this prefix still
    /// on the path, while requests through a <c>{proxy+}</c> resource arrive without it. The
    /// open routes are all named resources, so the prefix is stripped before routing.
    /// </summary>
    public string? BasePath { get; }

    /// <summary>The token issuer this pool signs with. Also the OIDC discovery authority.</summary>
    public string Issuer => $"https://cognito-idp.{Region}.amazonaws.com/{UserPoolId}";

    public static ApiSettings From(IConfiguration configuration) => new(
        region: configuration["AWS_REGION"] ?? DefaultRegion,
        userPoolId: configuration.Require("USER_POOL_ID"),
        clientId: configuration.Require("USER_POOL_CLIENT_ID"),
        adminGroup: configuration["ADMIN_GROUP"] ?? DefaultAdminGroup,
        allowedOrigins: (configuration["ALLOWED_ORIGINS"] ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
        basePath: NormalizeBasePath(configuration["API_BASE_PATH"]));

    /// <summary>Accepts "p/x", "/p/x" or "/p/x/"; returns "/p/x", or null for empty or "/".</summary>
    private static string? NormalizeBasePath(string? value)
    {
        var trimmed = (value ?? "").Trim().Trim('/');
        return trimmed.Length == 0 ? null : "/" + trimmed;
    }
}
