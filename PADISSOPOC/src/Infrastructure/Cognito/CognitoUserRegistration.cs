using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>The app client self-service registration runs against. No IAM credentials involved.</summary>
public sealed record CognitoRegistrationOptions(string ClientId);

/// <summary>
/// Cognito's unauthenticated registration operations. These take an app client id rather
/// than IAM credentials, which is what makes them safe behind public endpoints — a caller
/// can do no more here than they could against Cognito directly.
///
/// The one exception is <see cref="IsUsernameAvailableAsync"/>, which uses ListUsers and
/// therefore does need IAM.
/// </summary>
public sealed class CognitoUserRegistration(
    IAmazonCognitoIdentityProvider cognito,
    CognitoRegistrationOptions options) : IUserRegistration
{
    public const string StagedUsernameAttribute = "custom:signup_username";

    public async Task<RegistrationStarted> SignUpAsync(NewAccount account, CancellationToken ct = default)
    {
        var attributes = new List<AttributeType>
        {
            new() { Name = "email", Value = account.Email },
            new() { Name = StagedUsernameAttribute, Value = account.ChosenUsername },
        };

        if (!string.IsNullOrWhiteSpace(account.GivenName))
        {
            attributes.Add(new AttributeType { Name = "given_name", Value = account.GivenName });
        }
        if (!string.IsNullOrWhiteSpace(account.FamilyName))
        {
            attributes.Add(new AttributeType { Name = "family_name", Value = account.FamilyName });
        }

        try
        {
            var response = await cognito.SignUpAsync(new SignUpRequest
            {
                ClientId = options.ClientId,
                Username = account.AccountId,
                Password = account.Password,
                UserAttributes = attributes,
            }, ct);

            return new RegistrationStarted(
                account.AccountId,
                response.UserConfirmed ?? false,
                response.CodeDeliveryDetails?.Destination);
        }
        catch (InvalidPasswordException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
        catch (InvalidParameterException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
        catch (UsernameExistsException)
        {
            // The account id is a fresh identifier, so this means a collision on it rather
            // than on anything the user chose. Not actionable by the caller.
            throw new DirectoryValidationException("Could not create the account. Try again.");
        }
    }

    public async Task ConfirmAsync(string accountId, string code, CancellationToken ct = default)
    {
        try
        {
            await cognito.ConfirmSignUpAsync(new ConfirmSignUpRequest
            {
                ClientId = options.ClientId,
                Username = accountId,
                ConfirmationCode = code,
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
        catch (AliasExistsException)
        {
            // Someone claimed the staged name between sign-up and confirmation.
            throw new AliasAlreadyTakenException("that username");
        }
        catch (NotAuthorizedException)
        {
            // Cognito's response when the account is already confirmed.
            throw new DirectoryValidationException("This account is already confirmed.");
        }
        catch (Exception ex) when (ex is UserNotFoundException or ResourceNotFoundException)
        {
            // ConfirmSignUp reports an unknown user as ResourceNotFoundException
            // ("Username/client id combination not found"), not UserNotFoundException.
            // The same exception would be raised by a misconfigured ClientId — which would
            // turn every request into a 404 rather than surfacing the real fault, so the
            // original message is kept in the log by the exception handler.
            throw new UserNotFoundInDirectoryException(accountId);
        }
    }

    public async Task<string?> ResendCodeAsync(string accountId, CancellationToken ct = default)
    {
        try
        {
            var response = await cognito.ResendConfirmationCodeAsync(new ResendConfirmationCodeRequest
            {
                ClientId = options.ClientId,
                Username = accountId,
            }, ct);

            return response.CodeDeliveryDetails?.Destination;
        }
        catch (Exception ex) when (ex is UserNotFoundException or ResourceNotFoundException)
        {
            // As above: an unknown user surfaces as ResourceNotFoundException here.
            throw new UserNotFoundInDirectoryException(accountId);
        }
        catch (InvalidParameterException ex)
        {
            throw new DirectoryValidationException(ex.Message);
        }
    }

    public async Task<bool> IsUsernameAvailableAsync(
        string userPoolId, string username, CancellationToken ct = default)
    {
        // preferred_username is one of the few filterable attributes. custom: attributes are
        // not, so a name staged on an unconfirmed account cannot be seen here — two people
        // can still race for the same name and the loser fails at confirmation.
        var response = await cognito.ListUsersAsync(new ListUsersRequest
        {
            UserPoolId = userPoolId,
            Filter = $"preferred_username = \"{username.Replace("\"", "\\\"")}\"",
            Limit = 1,
        }, ct);

        return response.Users.Count == 0;
    }
}
