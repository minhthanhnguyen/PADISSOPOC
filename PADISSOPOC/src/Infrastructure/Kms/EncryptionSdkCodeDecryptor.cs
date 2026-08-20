using AWS.Cryptography.EncryptionSDK;
using AWS.Cryptography.MaterialProviders;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Kms;

/// <summary>
/// Unwraps the one-time code Cognito passes to a custom sender trigger.
///
/// Cognito envelope-encrypts it with the AWS Encryption SDK under a customer-managed KMS
/// key, so <c>kms:Decrypt</c> alone will not open it — though the role still needs that
/// permission, which the SDK uses internally to unwrap the data key.
/// </summary>
public sealed class EncryptionSdkCodeDecryptor : ICodeDecryptor
{
    private readonly ESDK _esdk;
    private readonly IKeyring _keyring;

    public EncryptionSdkCodeDecryptor(string keyArn)
    {
        var materialProviders = new MaterialProviders(new MaterialProvidersConfig());
        _keyring = materialProviders.CreateAwsKmsKeyring(new CreateAwsKmsKeyringInput
        {
            KmsKeyId = keyArn,
            KmsClient = new Amazon.KeyManagementService.AmazonKeyManagementServiceClient(),
        });

        // Cognito encrypts with a NON-committing algorithm suite. The SDK default,
        // REQUIRE_ENCRYPT_REQUIRE_DECRYPT, rejects those with InvalidAlgorithmSuiteInfoOnDecrypt.
        // ALLOW_DECRYPT permits reading them while still requiring commitment on encrypt.
        _esdk = new ESDK(new AwsEncryptionSdkConfig
        {
            CommitmentPolicy = ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        });
    }

    public string Decrypt(string ciphertext)
    {
        var output = _esdk.Decrypt(new DecryptInput
        {
            Ciphertext = new MemoryStream(Convert.FromBase64String(ciphertext)),
            Keyring = _keyring,
        });

        return System.Text.Encoding.UTF8.GetString(output.Plaintext.ToArray());
    }
}
