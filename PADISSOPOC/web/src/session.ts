/**
 * The signed-in session, as issued by the management API.
 *
 * Every sign-in — password, one-time code, passkey — goes through the API, which returns
 * tokens from a server-side app client with a secret. Amplify never signs anyone in, so it
 * holds no session of its own: `auth-config.ts` installs a token provider that serves these
 * tokens to `fetchAuthSession`, `fetchUserAttributes`, the profile pages and passkey
 * management, and refreshes them through the API when they expire.
 */
import { decodeJWT } from 'aws-amplify/auth';
import { logout, refreshTokens } from './api-client';

const STORAGE_KEY = 'padisso.api-session';

/** Refresh this long before expiry, so a request never goes out with a token about to lapse. */
const REFRESH_MARGIN_MS = 60_000;

export type ApiSession = {
  idToken: string;
  accessToken: string;
  refreshToken: string | null;
  /** Epoch milliseconds. Derived from the API's expiresIn when the tokens were issued. */
  expiresAt: number;
};

type IssuedTokens = {
  idToken: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  expiresIn: number;
};

export function saveSession(tokens: IssuedTokens, previousRefreshToken: string | null = null): ApiSession {
  if (!tokens.idToken || !tokens.accessToken) {
    throw new Error('Sign-in succeeded but returned no tokens.');
  }

  const session: ApiSession = {
    idToken: tokens.idToken,
    accessToken: tokens.accessToken,
    // A refresh returns no new refresh token (rotation is off), so the existing one is kept.
    refreshToken: tokens.refreshToken ?? previousRefreshToken,
    expiresAt: Date.now() + tokens.expiresIn * 1000,
  };

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Private browsing or a full quota. The session then lasts only this page load.
  }

  return session;
}

function readSession(): ApiSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const session = raw ? (JSON.parse(raw) as ApiSession) : null;
    return session?.idToken && session.accessToken ? session : null;
  } catch {
    return null;
  }
}

let inFlightRefresh: Promise<ApiSession | null> | null = null;

/**
 * The current session, refreshed through the API when it is expired, about to expire, or
 * `forceRefresh` is set — the profile pages force one so a changed email or username shows
 * in the ID token. Returns null when there is no session or it cannot be refreshed.
 *
 * Concurrent callers share one refresh, so a page mounting several components does not
 * send several refreshes.
 */
export async function currentSession(forceRefresh = false): Promise<ApiSession | null> {
  const session = readSession();
  if (!session) {
    return null;
  }

  if (!forceRefresh && session.expiresAt - REFRESH_MARGIN_MS > Date.now()) {
    return session;
  }

  inFlightRefresh ??= refresh(session).finally(() => {
    inFlightRefresh = null;
  });
  return inFlightRefresh;
}

async function refresh(session: ApiSession): Promise<ApiSession | null> {
  const username = decodeJWT(session.accessToken).payload.username as string | undefined;
  if (!session.refreshToken || !username) {
    clearSession();
    return null;
  }

  try {
    return saveSession(await refreshTokens(username, session.refreshToken), session.refreshToken);
  } catch {
    // Expired or revoked refresh token, or the API unreachable. Either way the user signs
    // in again rather than carrying a session that cannot be renewed.
    clearSession();
    return null;
  }
}

/**
 * Signs out: revokes the refresh token server-side, then forgets the session locally. The
 * local clear happens even if the revoke fails, so the browser is always signed out.
 */
export async function endSession(): Promise<void> {
  const session = readSession();
  clearSession();
  if (session?.refreshToken) {
    try {
      await logout(session.refreshToken);
    } catch {
      // Best effort — the tokens are gone from this browser either way.
    }
  }
}

export function clearSession(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do.
  }
}
