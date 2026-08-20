using Padi.Services.Authentication.Application.Abstractions;

namespace Padi.Services.Authentication.Application.Cognito;

public sealed record SignInCommand(
    string UserPoolId,
    string Username,
    string TriggerSource,
    string? ClientId,
    bool? NewDeviceUsed,
    IReadOnlyDictionary<string, string> UserAttributes);

/// <summary>
/// Audits a successful sign-in and stamps <c>custom:last_login</c>.
///
/// Runs inside the sign-in path, where an exception would fail the user's authentication.
/// Both steps are therefore isolated: a stale last-login is preferable to a failed login,
/// and an attribute-write failure must not lose the audit record.
/// </summary>
public sealed class RecordSignIn(IUserDirectory directory, IAuditLog audit, IClock clock)
{
    public const string LastLoginAttribute = "custom:last_login";

    public async Task ExecuteAsync(SignInCommand command, CancellationToken ct = default)
    {
        var signedInAt = clock.UtcNow;

        try
        {
            string? Attr(string name) =>
                command.UserAttributes.TryGetValue(name, out var v) ? v : null;

            audit.Record("SignIn", new Dictionary<string, object?>
            {
                ["timestamp"] = signedInAt.ToString("O"),
                ["userPoolId"] = command.UserPoolId,
                ["userName"] = command.Username,
                ["triggerSource"] = command.TriggerSource,
                ["clientId"] = command.ClientId,
                ["sub"] = Attr("sub"),
                ["email"] = Attr("email"),
                ["identities"] = Attr("identities"),
                ["padiId"] = Attr("custom:padi_id"),
                ["newDeviceUsed"] = command.NewDeviceUsed,
            });
        }
        catch (Exception ex)
        {
            audit.Error($"post-auth audit logging failed: {ex}");
        }

        try
        {
            await directory.SetAttributeAsync(
                command.UserPoolId, command.Username, LastLoginAttribute, signedInAt.ToString("O"), ct);
        }
        catch (Exception ex)
        {
            audit.Error($"post-auth last_login update failed: {ex}");
        }
    }
}
