using System.Security.Cryptography;
using System.Text;

namespace Padi.Services.Authentication.Domain.Identity;

/// <summary>
/// The shape of a Cognito username in this pool: <c>&lt;name key&gt;-&lt;unique part&gt;</c>.
///
/// The username can never change and is never typed, so it only has to be unique, and the
/// unique part guarantees that. The prefix exists for one reason. An unconfirmed account has
/// no <c>preferred_username</c> alias, and ListUsers cannot filter on
/// <c>custom:signup_username</c> where the chosen name is staged — but it can filter
/// <c>username ^= "…"</c>. Deriving the prefix from the chosen name makes a pending sign-up
/// findable by name with a single query.
///
/// The key is a truncated SHA-256 of the lowercased name rather than the name itself, so a
/// name the user later changes does not stay legible in an identifier that outlives it. It
/// is not a secret: a short name can be recovered by hashing guesses, and nothing may rely
/// on it being hidden.
///
/// The prefix records the name chosen at sign-up and is never updated, so it identifies
/// candidates, not matches. Callers must still compare <c>custom:signup_username</c>.
/// </summary>
public static class AccountIdentifier
{
    /// <summary>
    /// Hex characters of the hash kept — 64 bits. A collision is negligible, and harmless
    /// anyway, because every lookup verifies the staged name.
    /// </summary>
    public const int KeyLength = 16;

    public static string KeyFor(string chosenUsername) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(chosenUsername))))[..KeyLength];

    /// <summary>The ListUsers prefix for accounts created under this name, separator included.</summary>
    public static string PrefixFor(string chosenUsername) => KeyFor(chosenUsername) + "-";

    public static string Compose(string chosenUsername, string uniquePart) => PrefixFor(chosenUsername) + uniquePart;

    /// <summary>The pool compares usernames case-insensitively, so the key and matching must too.</summary>
    public static bool SameName(string a, string b) =>
        string.Equals(Normalize(a), Normalize(b), StringComparison.Ordinal);

    private static string Normalize(string name) => name.Trim().ToLowerInvariant();
}
