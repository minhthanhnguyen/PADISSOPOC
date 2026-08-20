using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Domain.MagicLink;

namespace Padi.Services.Authentication.Application.MagicLink;

public sealed record RedeemResult(bool Succeeded, IssuedTokens? Tokens);

/// <summary>
/// Exchanges a magic-link token for Cognito tokens.
///
/// The Cognito session used internally never reaches the caller, so its short lifetime
/// does not constrain how long a link stays clickable — only the token's own expiry does.
/// </summary>
public sealed class RedeemMagicLink(
    IMagicLinkTokenStore store,
    IAuthenticator authenticator,
    IClock clock)
{
    public async Task<RedeemResult> ExecuteAsync(string rawToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return new RedeemResult(false, null);
        }

        // Consumed before validation: an expired token is still spent, so a leaked link
        // cannot be retried once its window passes.
        var stored = await store.ConsumeAsync(MagicLinkToken.HashOf(rawToken), ct);
        if (stored is null || clock.UtcNow >= stored.ExpiresAt)
        {
            return new RedeemResult(false, null);
        }

        var tokens = await authenticator.AuthenticateAsync(stored.Username, ct);
        return new RedeemResult(true, tokens);
    }
}
