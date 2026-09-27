using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Infrastructure.Cognito;

/// <summary>
/// Choice-based (USER_AUTH) passwordless sign-in, relayed server-side on the sign-in client.
///
/// The browser used to run this against Cognito itself, which required ALLOW_USER_AUTH on
/// the public client — and Cognito always offers passwords under USER_AUTH, so that client
/// let anyone try passwords directly. Relaying it here is what lets the public client offer
/// no sign-in flow at all.
/// </summary>
public sealed class CognitoPasswordlessSignIn(
    IAmazonCognitoIdentityProvider cognito,
    CognitoSignInClient client) : IPasswordlessSignIn
{
    public async Task<SignInChallenge> StartAsync(
        string username, PasswordlessFactor factor, CancellationToken ct = default)
    {
        AdminInitiateAuthResponse response;
        try
        {
            response = await cognito.AdminInitiateAuthAsync(new AdminInitiateAuthRequest
            {
                UserPoolId = client.UserPoolId,
                ClientId = client.ClientId,
                AuthFlow = AuthFlowType.USER_AUTH,
                AuthParameters = new Dictionary<string, string>
                {
                    ["USERNAME"] = username,
                    ["PREFERRED_CHALLENGE"] = ChallengeName(factor),
                    ["SECRET_HASH"] = await client.SecretHashAsync(username, ct),
                },
            }, ct);
        }
        catch (Exception ex) when (Translate(ex) is { } translated)
        {
            throw translated;
        }

        var challenge = response.ChallengeName?.Value;

        // Cognito answers SELECT_CHALLENGE when the preferred factor is not available for
        // this user — no passkey registered, no verified phone, and so on.
        if (challenge != ChallengeName(factor))
        {
            throw new FactorUnavailableException(
                (response.AvailableChallenges ?? []).Where(c => c != "PASSWORD" && c != "PASSWORD_SRP").ToList());
        }

        var parameters = response.ChallengeParameters ?? [];
        return new SignInChallenge(
            factor,
            response.Session,
            CodeDestination: parameters.GetValueOrDefault("CODE_DELIVERY_DESTINATION"),
            CredentialRequestOptions: parameters.GetValueOrDefault("CREDENTIAL_REQUEST_OPTIONS"));
    }

    public async Task<SignInOutcome> AnswerAsync(
        string username, PasswordlessFactor factor, string session, string answer, CancellationToken ct = default)
    {
        AdminRespondToAuthChallengeResponse response;
        try
        {
            response = await cognito.AdminRespondToAuthChallengeAsync(new AdminRespondToAuthChallengeRequest
            {
                UserPoolId = client.UserPoolId,
                ClientId = client.ClientId,
                ChallengeName = ChallengeName(factor),
                Session = session,
                ChallengeResponses = new Dictionary<string, string>
                {
                    ["USERNAME"] = username,
                    [AnswerKey(factor)] = answer,
                    ["SECRET_HASH"] = await client.SecretHashAsync(username, ct),
                },
            }, ct);
        }
        catch (Exception ex) when (Translate(ex) is { } translated)
        {
            throw translated;
        }

        if (response.AuthenticationResult is { } result)
        {
            return SignInOutcome.Succeeded(CognitoTokens.From(result));
        }

        return SignInOutcome.Challenged(response.ChallengeName?.Value ?? "UNKNOWN");
    }

    private static string ChallengeName(PasswordlessFactor factor) => factor switch
    {
        PasswordlessFactor.EmailOtp => "EMAIL_OTP",
        PasswordlessFactor.SmsOtp => "SMS_OTP",
        PasswordlessFactor.Passkey => "WEB_AUTHN",
        _ => throw new ArgumentOutOfRangeException(nameof(factor)),
    };

    private static string AnswerKey(PasswordlessFactor factor) => factor switch
    {
        PasswordlessFactor.EmailOtp => "EMAIL_OTP_CODE",
        PasswordlessFactor.SmsOtp => "SMS_OTP_CODE",
        PasswordlessFactor.Passkey => "CREDENTIAL",
        _ => throw new ArgumentOutOfRangeException(nameof(factor)),
    };

    /// <summary>
    /// Cognito's failures, reduced to what a caller may learn. Anything not listed stays a 500,
    /// so an unexpected failure is visible rather than disguised as a wrong code.
    /// </summary>
    private static Exception? Translate(Exception ex) => ex switch
    {
        UserNotConfirmedException => new AccountNotConfirmedException(),
        CodeMismatchException or ExpiredCodeException =>
            new ChallengeFailedException("That code is not correct or has expired."),
        // Covers an unknown user, a rejected passkey assertion and an expired sign-in session.
        // One message for all, so the answer does not reveal which.
        NotAuthorizedException or UserNotFoundException =>
            new ChallengeFailedException("Sign-in failed. Start again."),
        TooManyRequestsException or LimitExceededException or TooManyFailedAttemptsException =>
            new TooManyAttemptsException(),
        _ => null,
    };
}
