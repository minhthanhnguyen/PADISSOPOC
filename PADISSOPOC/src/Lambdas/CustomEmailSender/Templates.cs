using System.Text.Json.Nodes;

namespace Padi.Services.Authentication.Cognito.CustomEmailSender;

public sealed record EmailTemplate(string Subject, string Html, string Text);

/// <summary>
/// Maps a Cognito trigger source to message content. Kept deliberately plain — if the
/// messaging service owns templates, replace these bodies with a template id and pass
/// the code through <c>Metadata</c> instead.
/// </summary>
public static class Templates
{
    public static EmailTemplate? For(string triggerSource, string? code, JsonObject? attrs)
    {
        var name = attrs?["given_name"]?.GetValue<string>();
        var hello = string.IsNullOrWhiteSpace(name) ? "Hello," : $"Hi {name},";

        return triggerSource switch
        {
            "CustomEmailSender_SignUp" => Code(
                "Verify your PADI account",
                $"{hello} use this code to finish setting up your account:",
                code),

            "CustomEmailSender_ResendCode" => Code(
                "Your PADI verification code",
                $"{hello} here is a new verification code:",
                code),

            // Passwordless email OTP and MFA both arrive here.
            "CustomEmailSender_Authentication" => Code(
                "Your PADI sign-in code",
                $"{hello} use this code to sign in:",
                code),

            "CustomEmailSender_ForgotPassword" => Code(
                "Reset your PADI password",
                $"{hello} use this code to reset your password:",
                code),

            "CustomEmailSender_UpdateUserAttribute" or
            "CustomEmailSender_VerifyUserAttribute" => Code(
                "Verify your details",
                $"{hello} use this code to confirm the change to your account:",
                code),

            "CustomEmailSender_AdminCreateUser" => Code(
                "Your PADI temporary password",
                $"{hello} an account has been created for you. Sign in with this temporary password:",
                code),

            "CustomEmailSender_AccountTakeOverNotification" => new EmailTemplate(
                "Unusual activity on your PADI account",
                $"<p>{hello}</p><p>We noticed a sign-in attempt that looked unusual. " +
                "If this was not you, please reset your password.</p>",
                $"{hello}\n\nWe noticed a sign-in attempt that looked unusual. " +
                "If this was not you, please reset your password."),

            _ => null,
        };
    }

    private static EmailTemplate? Code(string subject, string lead, string? code)
    {
        if (string.IsNullOrEmpty(code)) return null;
        return new EmailTemplate(
            subject,
            $"<p>{lead}</p><p style=\"font-size:24px;font-weight:600;letter-spacing:3px\">{code}</p>",
            $"{lead}\n\n{code}");
    }
}
