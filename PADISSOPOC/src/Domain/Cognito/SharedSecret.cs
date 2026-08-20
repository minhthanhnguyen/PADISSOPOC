using System.Security.Cryptography;
using System.Text;

namespace Padi.Services.Authentication.Domain.Cognito;

/// <summary>
/// Comparison for values that gate authentication. Always constant-time: a length- or
/// content-dependent comparison leaks the secret one byte at a time under timing analysis.
/// </summary>
public static class SharedSecret
{
    public static bool Matches(string? candidate, string? expected)
    {
        if (string.IsNullOrEmpty(candidate) || string.IsNullOrEmpty(expected))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(candidate),
            Encoding.UTF8.GetBytes(expected));
    }
}
