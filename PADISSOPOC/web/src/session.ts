/**
 * Tokens obtained from the management API's `/public/login`.
 *
 * Amplify's own sign-in stores its tokens itself. This holds the ones the API hands back, so
 * the two are bridged rather than parallel: `auth-config.ts` installs a token provider that
 * prefers these when present and otherwise defers to Amplify's store. Everything downstream
 * — `fetchAuthSession`, `fetchUserAttributes`, the profile pages — then works the same way
 * regardless of which route the user signed in by.
 */
const STORAGE_KEY = 'padisso.api-session';

export type ApiSession = {
  idToken: string;
  accessToken: string;
  refreshToken: string | null;
  /** Epoch milliseconds. Derived from the API's expiresIn at the moment of sign-in. */
  expiresAt: number;
};

export function saveSession(tokens: {
  idToken: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  expiresIn: number;
}): void {
  if (!tokens.idToken || !tokens.accessToken) {
    throw new Error('Sign-in succeeded but returned no tokens.');
  }

  const session: ApiSession = {
    idToken: tokens.idToken,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresAt: Date.now() + tokens.expiresIn * 1000,
  };

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Private browsing or a full quota. The session then lasts only this page load.
  }
}

/**
 * Returns null once the access token has expired. There is no refresh here — the refresh
 * token is stored but never exchanged, so the session simply ends and the user signs in
 * again. See the known gaps.
 */
export function loadSession(): ApiSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }

    const session = JSON.parse(raw) as ApiSession;
    if (!session.idToken || !session.accessToken || session.expiresAt <= Date.now()) {
      clearSession();
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do.
  }
}
