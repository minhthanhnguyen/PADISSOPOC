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

    private ApiSettings(string region, string userPoolId, string clientId, string adminGroup)
    {
        Region = region;
        UserPoolId = userPoolId;
        ClientId = clientId;
        AdminGroup = adminGroup;
    }

    public string Region { get; }

    public string UserPoolId { get; }

    public string ClientId { get; }

    public string AdminGroup { get; }

    /// <summary>The token issuer this pool signs with. Also the OIDC discovery authority.</summary>
    public string Issuer => $"https://cognito-idp.{Region}.amazonaws.com/{UserPoolId}";

    public static ApiSettings From(IConfiguration configuration) => new(
        region: configuration["AWS_REGION"] ?? DefaultRegion,
        userPoolId: configuration.Require("USER_POOL_ID"),
        clientId: configuration.Require("USER_POOL_CLIENT_ID"),
        adminGroup: configuration["ADMIN_GROUP"] ?? DefaultAdminGroup);
}
