using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Padi.Services.Authentication.Application.Cognito;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Padi.Services.Authentication.Cognito.VerifyAuthChallenge;

/// <summary>
/// Cognito VerifyAuthChallengeResponse trigger. Confirms the exchange was started through the
/// magic-link app client by the one component holding the admin proof; the user's own
/// credential — the magic-link token — was already checked against the store before this point.
/// </summary>
public static class Function
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static Settings? _settings;

    public static async Task<JsonObject> Handler(JsonObject evt, ILambdaContext _)
    {
        var settings = await LoadAsync();

        var request = evt["request"]!.AsObject();
        var callerClientId = evt["callerContext"]?["clientId"]?.GetValue<string>();
        var proof = request["clientMetadata"]?.AsObject()?["admin_proof"]?.GetValue<string>();
        var answer = request["challengeAnswer"]?.GetValue<string>();

        evt["response"]!.AsObject()["answerCorrect"] = CustomAuthChallenge.Verify(
            callerClientId, settings.MagicLinkClientId, proof, answer, settings.AdminProof);

        return evt;
    }

    private sealed record Settings(string AdminProof, string MagicLinkClientId);

    /// <summary>
    /// Read at runtime, once per execution environment, rather than from environment
    /// variables: those are returned in plain text by lambda:GetFunctionConfiguration, which
    /// broad read-only roles include.
    ///
    /// The client id comes from Parameter Store rather than an environment variable for a
    /// different reason. This function is one of the pool's triggers, so an environment
    /// variable referencing a client of the same pool would make the pool depend on itself
    /// in CloudFormation. Only the parameter's fixed name is configured here.
    ///
    /// A failed load is not cached, so a transient error costs one invocation rather than
    /// every invocation until the next cold start.
    /// </summary>
    private static async Task<Settings> LoadAsync()
    {
        if (_settings is not null)
        {
            return _settings;
        }

        await Gate.WaitAsync();
        try
        {
            if (_settings is not null)
            {
                return _settings;
            }

            using var secrets = new AmazonSecretsManagerClient();
            using var ssm = new AmazonSimpleSystemsManagementClient();

            var proof = await secrets.GetSecretValueAsync(
                new GetSecretValueRequest { SecretId = Require("ADMIN_PROOF_SECRET_ID") });
            var clientId = await ssm.GetParameterAsync(
                new GetParameterRequest { Name = Require("MAGIC_LINK_CLIENT_ID_PARAMETER") });

            return _settings = new Settings(proof.SecretString, clientId.Parameter.Value);
        }
        finally
        {
            Gate.Release();
        }
    }

    private static string Require(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"Missing required environment variable: {name}");
}
