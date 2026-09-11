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
        if (!string.IsNullOrWhiteSpace(account.MiddleInitial))
        {
            // The initial lives in the standard middle_name attribute — there is no
            // dedicated Cognito attribute for an initial, and a custom one would mean a
            // schema change the live pool cannot take.
            attributes.Add(new AttributeType { Name = "middle_name", Value = account.MiddleInitial });
        }
        if (!string.IsNullOrWhiteSpace(account.FamilyName))
        {
            attributes.Add(new AttributeType { Name = "family_name", Value = account.FamilyName });
        }
        if (!string.IsNullOrWhiteSpace(account.Birthdate))
        {
            attributes.Add(new AttributeType { Name = "birthdate", Value = account.Birthdate });
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
        catch (UserNotFoundException)
        {
            throw new UserNotFoundInDirectoryException(accountId);
        }

        // ResourceNotFoundException is deliberately NOT caught. With the pool reachable and
        // PreventUserExistenceErrors on, an unknown user produces ExpiredCode or
        // CodeMismatch above — so this exception means the *client id* could not be
        // resolved, which is a deployment fault. Letting it surface as a 500 keeps that
        // visible instead of reporting a misleading "no such user".
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
        catch (UserNotFoundException)
        {
            // ResendConfirmationCode returns simulated CodeDeliveryDetails for an unknown
            // user rather than throwing, so this is rare. ResourceNotFoundException is left
            // uncaught for the same reason as in ConfirmAsync.
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
