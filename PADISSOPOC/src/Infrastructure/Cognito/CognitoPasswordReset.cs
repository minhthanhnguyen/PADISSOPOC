using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// Password reset via Cognito's ForgotPassword and ConfirmForgotPassword.
///
/// Unlike sign-in, these are client-id-only operations and need no IAM — the app client id
/// is the only credential involved, exactly as it would be if the browser called Cognito
/// itself. Routing them through the API buys throttling and a single audited front door,
/// not extra privilege.
/// </summary>
public sealed class CognitoPasswordReset(
    IAmazonCognitoIdentityProvider cognito,
    CognitoPasswordOptions options) : IPasswordReset
{
    public async Task<string?> StartAsync(string username, CancellationToken ct = default)
    {
        try
        {
            var response = await cognito.ForgotPasswordAsync(new ForgotPasswordRequest
            {
                ClientId = options.ClientId,
                Username = username,
            }, ct);

            // With PreventUserExistenceErrors on, Cognito fabricates this for an unknown
            // user rather than failing. Passed through as-is so the caller cannot tell.
            return response.CodeDeliveryDetails?.Destination;
        }
        catch (InvalidParameterException ex)
        {
            // Raised when the account has no verified email or phone to send a code to.
            // Reported as a plain validation failure — naming the reason would confirm the
            // account exists.
            throw new DirectoryValidationException(
                $"A reset code could not be sent. {ex.Message}");
        }
        catch (LimitExceededException)
        {
            throw new TooManyAttemptsException();
        }
    }

    public async Task CompleteAsync(
        string username, string code, string newPassword, CancellationToken ct = default)
    {
        try
        {
            await cognito.ConfirmForgotPasswordAsync(new ConfirmForgotPasswordRequest
            {
                ClientId = options.ClientId,
                Username = username,
                ConfirmationCode = code,
                Password = newPassword,
            }, ct);
        }
        catch (InvalidPasswordException ex)
        {
            // The pool's password policy. Safe to surface — it describes the policy, not
            // the account.
            throw new DirectoryValidationException(ex.Message);
        }
        catch (Exception ex) when (ex is CodeMismatchException or ExpiredCodeException)
        {
            throw new DirectoryValidationException("That code is not correct or has expired.");
        }
        catch (Exception ex) when (ex is UserNotFoundException or ResourceNotFoundException)
        {
            // Deliberately identical to a wrong code: a distinct "no such user" here would
            // undo the enumeration protection that StartAsync preserves.
            throw new DirectoryValidationException("That code is not correct or has expired.");
        }
        catch (LimitExceededException)
        {
            throw new TooManyAttemptsException();
        }
    }
}
