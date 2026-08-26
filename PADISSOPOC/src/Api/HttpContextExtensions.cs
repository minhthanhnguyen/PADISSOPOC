using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Api;

public static class HttpContextExtensions
{
    private const string BearerPrefix = "Bearer ";

    /// <summary>
    /// The caller's raw access token.
    ///
    /// Forwarded verbatim to Cognito on the self-service path so Cognito applies the app
    /// client's own attribute permissions, rather than the service's IAM role. The token has
    /// already been validated by the authentication middleware — and by API Gateway's
    /// authorizer before that — so this only has to extract it.
    /// </summary>
    public static string AccessToken(this HttpContext http)
    {
        var header = http.Request.Headers.Authorization.ToString();

        return header.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase)
            ? header[BearerPrefix.Length..].Trim()
            : throw new DirectoryValidationException("A bearer access token is required.");
    }
}
