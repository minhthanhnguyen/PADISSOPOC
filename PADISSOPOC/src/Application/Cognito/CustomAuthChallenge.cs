using Padi.Services.Authentication.Domain.Cognito;

namespace Padi.Services.Authentication.Application.Cognito;

public sealed record ChallengeDecision(bool IssueTokens, bool FailAuthentication, string? ChallengeName);

/// <summary>
/// Decision logic for Cognito's custom-auth triggers. Pure — no I/O, no AWS types — so
/// the whole flow is unit-testable and the Lambdas that host it carry no SDKs.
/// </summary>
public static class CustomAuthChallenge
{
    public const string ChallengeName = "CUSTOM_CHALLENGE";

    /// <summary>
    /// First call issues the challenge; later calls settle on whatever the previous
    /// answer produced.
    /// </summary>
    public static ChallengeDecision Define(IReadOnlyList<bool> priorResults)
    {
        if (priorResults.Count == 0)
        {
            return new ChallengeDecision(IssueTokens: false, FailAuthentication: false, ChallengeName);
        }

        var lastAnswerCorrect = priorResults[^1];
        return new ChallengeDecision(lastAnswerCorrect, !lastAnswerCorrect, ChallengeName: null);
    }

    /// <summary>
    /// The magic-link token was already validated against the store before this challenge
    /// began, so creating it is a formality — Cognito simply requires the trigger to exist.
    /// </summary>
    public static IReadOnlyDictionary<string, string> CreatePrivateParameters() =>
        new Dictionary<string, string> { ["expected"] = "MAGIC" };

    /// <summary>
    /// Accepts only an exchange started through the magic-link app client by a caller holding
    /// the shared admin proof.
    ///
    /// The proof alone was not enough. Cognito does not tell a trigger whether the flow was
    /// admin-initiated, so while the public browser client allowed custom auth, anyone who
    /// learned the proof could start the flow there — no AWS credentials needed — and sign in
    /// as any user. Custom auth now lives only on a server-side client that has a secret,
    /// and this check pins it there even if the public client is ever reconfigured.
    /// </summary>
    public static bool Verify(
        string? callerClientId, string expectedClientId,
        string? proofFromMetadata, string? challengeAnswer, string expectedProof) =>
        !string.IsNullOrEmpty(expectedClientId) &&
        string.Equals(callerClientId, expectedClientId, StringComparison.Ordinal) &&
        SharedSecret.Matches(proofFromMetadata, expectedProof) &&
        SharedSecret.Matches(challengeAnswer, expectedProof);
}
