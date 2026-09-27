/**
 * Mirrors src/Domain/Identity/PhoneNumberRules.cs so the sign-up form can reject a bad number
 * before any request. Keep the two in step.
 *
 * Cognito stores phone_number in E.164 — a plus sign, the country code, digits only. Common
 * formatting is stripped, so "+1 (206) 555-0123" becomes "+12065550123". The country code is
 * required, never guessed.
 */
const E164 = /^\+[1-9]\d{6,14}$/;
const FORMATTING = /[\s\-.()]/g;

export const PHONE_HINT = 'Optional. Include the country code, e.g. +1 206 555 0123.';

/** Returns the E.164 form, `null` for blank input, or throws with a message for bad input. */
export function normalizePhoneNumber(candidate: string): string | null {
  const trimmed = candidate.trim();
  if (trimmed.length === 0) {
    return null;
  }

  const compact = trimmed.replace(FORMATTING, '');
  if (!E164.test(compact)) {
    throw new Error('Phone number must include the country code, e.g. +1 206 555 0123.');
  }
  return compact;
}
