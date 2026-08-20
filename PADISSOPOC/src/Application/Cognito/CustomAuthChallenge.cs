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
    /// Accepts only a caller holding the shared admin proof, which in practice means the
    /// one Lambda permitted to call AdminInitiateAuth. Both the metadata copy and the
    /// challenge answer must match, so neither alone is sufficient.
    /// </summary>
    public static bool Verify(string? proofFromMetadata, string? challengeAnswer, string expectedProof) =>
        SharedSecret.Matches(proofFromMetadata, expectedProof) &&
        SharedSecret.Matches(challengeAnswer, expectedProof);
}
