/**
 * Mirrors src/Domain/Identity/UsernameRules.cs.
 *
 * Cognito constrains the `Username` request parameter to 1–128 characters matching
 * `[\p{L}\p{M}\p{S}\p{N}\p{P}]+` — a set that excludes whitespace entirely. It does *not*
 * apply that constraint where `preferred_username` is written: attribute values allow up to
 * 2048 characters with no pattern, so Cognito will happily store "john smith" as an alias
 * and then reject it on sign-in and password reset. Validating here is what keeps the two
 * consistent; the PostConfirmation trigger enforces the same rule server-side.
 */
export const MAX_USERNAME_LENGTH = 128;

/** The Cognito Username pattern, verbatim. Do not widen. */
const ALLOWED = /^[\p{L}\p{M}\p{S}\p{N}\p{P}]+$/u;

/** Returns null when valid, otherwise a message naming the problem. */
export function validateUsername(candidate: string): string | null {
  if (!candidate) {
    return 'Username is required.';
  }

  if (candidate !== candidate.trim()) {
    return 'Username cannot start or end with a space.';
  }

  if (candidate.length > MAX_USERNAME_LENGTH) {
    return `Username cannot be longer than ${MAX_USERNAME_LENGTH} characters.`;
  }

  if (/\s/u.test(candidate)) {
    return 'Username cannot contain spaces.';
  }

  // .NET matches \p{S} against UTF-16 code units, so an astral-plane character such as an
  // emoji lands in the surrogate category and fails the server-side check — while this
  // regex, with the /u flag, matches by code point and would accept it. Rejecting here
  // keeps the two in agreement, erring toward the stricter side: the cost is choosing a
  // different name, not a confirmation that throws after the account already exists.
  if (/[\u{10000}-\u{10FFFF}]/u.test(candidate)) {
    return 'Username cannot contain emoji or other extended characters.';
  }

  return ALLOWED.test(candidate)
    ? null
    : 'Username contains a character Cognito does not accept.';
}

export const USERNAME_RULES =
  `Up to ${MAX_USERNAME_LENGTH} characters, no spaces. Letters, digits and punctuation are allowed.`;
