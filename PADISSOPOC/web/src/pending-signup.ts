/**
 * Maps a chosen sign-up name to the opaque Cognito username behind it.
 *
 * `preferred_username` is only assigned once the account is confirmed, so between sign-up
 * and confirmation the account has no alias — the UUID is the only identifier that
 * `confirmSignUp` or `resendSignUpCode` will accept, and the user has never seen it.
 * Holding it here lets a reload, or a redirect from the login page, recover.
 *
 * Browser-local, so it does not survive a different device. A user who abandons
 * confirmation and returns elsewhere has to sign up again; the chosen name is still free
 * because it never became an alias.
 */
const PREFIX = 'padisso.pending-signup.';

const keyFor = (chosenName: string) => `${PREFIX}${chosenName.trim().toLowerCase()}`;

export function rememberAccountId(chosenName: string, accountId: string): void {
  try {
    localStorage.setItem(keyFor(chosenName), accountId);
  } catch {
    // Private browsing or a full quota. Recovery is a convenience, not a requirement.
  }
}

export function recallAccountId(chosenName: string): string | null {
  try {
    return localStorage.getItem(keyFor(chosenName));
  } catch {
    return null;
  }
}

export function forgetAccountId(chosenName: string): void {
  try {
    localStorage.removeItem(keyFor(chosenName));
  } catch {
    // Nothing to do.
  }
}
