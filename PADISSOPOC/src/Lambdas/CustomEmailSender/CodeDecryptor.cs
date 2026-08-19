using AWS.Cryptography.EncryptionSDK;
using AWS.Cryptography.MaterialProviders;

namespace Padi.Services.Authentication.Cognito.CustomEmailSender;

/// <summary>
/// Decrypts the one-time code Cognito passes in <c>request.code</c>.
///
/// Cognito encrypts it with the AWS Encryption SDK using a customer-managed KMS key,
/// so this is an envelope-encrypted message — <c>kms:Decrypt</c> on its own will not
/// open it. The Lambda role still needs kms:Decrypt on the key, which the SDK calls
/// under the covers to unwrap the data key.
/// </summary>
public static class CodeDecryptor
{
    private static readonly Lazy<(ESDK Esdk, IKeyring Keyring)> Client = new(() =>
    {
        var keyArn = Environment.GetEnvironmentVariable("KEY_ARN")
                     ?? throw new InvalidOperationException("Missing required environment variable: KEY_ARN");

        var materialProviders = new MaterialProviders(new MaterialProvidersConfig());
        var keyring = materialProviders.CreateAwsKmsKeyring(new CreateAwsKmsKeyringInput
        {
            KmsKeyId = keyArn,
            KmsClient = new Amazon.KeyManagementService.AmazonKeyManagementServiceClient(),
        });

        // Cognito encrypts codes with a NON-committing algorithm suite. The SDK default,
        // REQUIRE_ENCRYPT_REQUIRE_DECRYPT, rejects those outright with
        // InvalidAlgorithmSuiteInfoOnDecrypt. ALLOW_DECRYPT permits reading them while
        // still requiring commitment on anything this code encrypts itself.
        var esdk = new ESDK(new AwsEncryptionSdkConfig
        {
            CommitmentPolicy = ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        });
        return (esdk, keyring);
    });

    public static string Decrypt(string base64Ciphertext)
    {
        var (esdk, keyring) = Client.Value;

        var output = esdk.Decrypt(new DecryptInput
        {
            Ciphertext = new MemoryStream(Convert.FromBase64String(base64Ciphertext)),
            Keyring = keyring,
        });

        return System.Text.Encoding.UTF8.GetString(output.Plaintext.ToArray());
    }
}
