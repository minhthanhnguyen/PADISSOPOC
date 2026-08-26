using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// Self-service operations carried out with the caller's own access token.
///
/// None of these calls use the service's IAM credentials, so Cognito enforces the app
/// client's attribute write permissions on every one of them. That is the point: a bug in
/// the API's authorization cannot let a user write an attribute the client cannot write.
/// </summary>
public sealed class CognitoUserSelfService(IAmazonCognitoIdentityProvider cognito) : IUserSelfService
{
    public async Task<IReadOnlyDictionary<string, string>> GetAsync(
        string accessToken, CancellationToken ct = default)
    {
        var user = await cognito.GetUserAsync(new GetUserRequest { AccessToken = accessToken }, ct);
        return user.UserAttributes.ToDictionary(a => a.Name, a => a.Value);
    }

    public async Task UpdateAttributesAsync(
        string accessToken, IReadOnlyDictionary<string, string> attributes, CancellationToken ct = default)
    {
        try
        {
            await cognito.UpdateUserAttributesAsync(new UpdateUserAttributesRequest
            {
                AccessToken = accessToken,
                UserAttributes = [.. attributes.Select(kv => new AttributeType { Name = kv.Key, Value = kv.Value })],
            }, ct);
        }
        catch (AliasExistsException)
        {
            throw new AliasAlreadyTakenException(
                attributes.TryGetValue("preferred_username", out var alias) ? alias : "value");
        }
        catch (InvalidParameterException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
    }

    public async Task<string?> StartEmailChangeAsync(
        string accessToken, string newEmail, CancellationToken ct = default)
    {
        try
        {
            var response = await cognito.UpdateUserAttributesAsync(new UpdateUserAttributesRequest
            {
                AccessToken = accessToken,
                UserAttributes = [new AttributeType { Name = "email", Value = newEmail }],
            }, ct);

            // The pool keeps the original address active until the new one is verified, so
            // this destination is the address being verified, not the one still in use.
            return response.CodeDeliveryDetailsList?.FirstOrDefault()?.Destination;
        }
        catch (AliasExistsException)
        {
            throw new AliasAlreadyTakenException(newEmail);
        }
        catch (InvalidParameterException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
    }

    public async Task ConfirmEmailChangeAsync(string accessToken, string code, CancellationToken ct = default)
    {
        try
        {
            await cognito.VerifyUserAttributeAsync(new VerifyUserAttributeRequest
            {
                AccessToken = accessToken,
                AttributeName = "email",
                Code = code,
            }, ct);
        }
        catch (CodeMismatchException)
        {
            throw new DirectoryValidationException("That code is not correct.");
        }
        catch (ExpiredCodeException)
        {
            throw new DirectoryValidationException("That code has expired. Request a new one.");
        }
    }
}
