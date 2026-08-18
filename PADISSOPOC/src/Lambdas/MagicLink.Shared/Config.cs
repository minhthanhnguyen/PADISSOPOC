namespace Padi.Services.Authentication.MagicLink.Shared;

/// <summary>Environment-variable backed configuration shared across the magic-link functions.</summary>
public static class Config
{
    public static string Table      => Require("MAGIC_LINK_TABLE");
    public static string BaseUrl    => Require("MAGIC_LINK_BASE_URL");
    public static string UserPoolId => Require("USER_POOL_ID");
    public static string ClientId   => Require("CLIENT_ID");
    public static string AdminProof => Require("ADMIN_PROOF");

    /// <summary>Verified SES identity. Only read when the email channel is used.</summary>
    public static string EmailFrom => Require("MAGIC_LINK_EMAIL_FROM");

    /// <summary>Alphanumeric SMS sender ID. Optional — unsupported in some countries (incl. US).</summary>
    public static string? SmsSenderId => Environment.GetEnvironmentVariable("MAGIC_LINK_SMS_SENDER_ID");

    public static int TtlMin => int.Parse(Environment.GetEnvironmentVariable("MAGIC_LINK_TTL_MIN") ?? "15");

    private static string Require(string key) =>
        Environment.GetEnvironmentVariable(key)
        ?? throw new InvalidOperationException($"Missing required environment variable: {key}");
}
