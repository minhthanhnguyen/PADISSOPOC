/**
 * Thin client for the PADISSO management API.
 *
 * VITE_API_BASE_URL is the **API root**, not the public prefix — route paths below add
 * their own `/public`, `/me` or `/admin` segment. With a base of
 * `https://api.global-np.padi.com/p/padi-auth-poc`, sign-up posts to
 * `https://api.global-np.padi.com/p/padi-auth-poc/public/signup`.
 *
 * Only the `/public` routes are used so far; everything else in the app still talks to
 * Cognito directly through Amplify.
 */
const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');

// The public endpoints are usually quoted as ".../p/padi-auth-poc/public", so pasting that
// whole string in here is the natural mistake — and it produces /public/public/signup,
// which 404s with nothing to suggest why.
if (BASE_URL.endsWith('/public')) {
  throw new Error(
    'VITE_API_BASE_URL must be the API root, without the trailing /public — ' +
      'route paths add it. Use https://api.global-np.padi.com/p/padi-auth-poc',
  );
}

export type RegistrationStarted = {
  /** The opaque Cognito username. Required to confirm — the chosen name will not work. */
  accountId: string;
  confirmed: boolean;
  codeDestination: string | null;
};

export type RegisterInput = {
  username: string;
  password: string;
  email: string;
  givenName?: string;
  familyName?: string;
};

/** Raised for any non-2xx response, carrying the message the API supplied. */
export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export type IssuedTokens = {
  idToken: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  expiresIn: number;
  tokenType: string | null;
};

export type CodeResent = {
  /** Masked destination Cognito reported, e.g. m***@g***.com. Null if it did not say. */
  codeDestination: string | null;
};

export function isApiConfigured(): boolean {
  return BASE_URL.length > 0;
}

export async function registerAccount(input: RegisterInput): Promise<RegistrationStarted> {
  return post<RegistrationStarted>('/public/signup', input);
}

/**
 * Password sign-in. Throws ApiError with status 401 for bad credentials and 403 when the
 * account exists but has never been confirmed.
 */
export async function login(username: string, password: string): Promise<IssuedTokens> {
  return post<IssuedTokens>('/public/login', { username, password });
}

/** Resolves on success; throws ApiError with the API's message otherwise. */
export async function confirmRegistration(accountId: string, code: string): Promise<void> {
  await post<void>('/public/signup/confirm', { accountId, code });
}

export async function resendRegistrationCode(accountId: string): Promise<CodeResent> {
  return post<CodeResent>('/public/signup/resend', { accountId });
}

async function post<T>(path: string, body: unknown): Promise<T> {
  if (!BASE_URL) {
    throw new ApiError(0, 'VITE_API_BASE_URL is not set, so the API cannot be reached.');
  }

  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    // fetch rejects on network failure and on a blocked CORS response, which are
    // indistinguishable from script — say so rather than guessing at one.
    throw new ApiError(0, 'Could not reach the API. Check that it is running and that this origin is allowed.');
  }

  if (!response.ok) {
    throw new ApiError(response.status, await readError(response));
  }

  return readBody<T>(response);
}

/**
 * Not every success carries a body — confirmation answers 204. Calling response.json()
 * unconditionally would turn a successful confirmation into a parse error.
 */
async function readBody<T>(response: Response): Promise<T> {
  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  return (text.length > 0 ? JSON.parse(text) : undefined) as T;
}

/**
 * The API returns RFC 7807 problem details. Model-validation failures carry a nested
 * `errors` map; everything else puts a usable sentence in `title`.
 */
async function readError(response: Response): Promise<string> {
  try {
    const problem = await response.json();

    if (problem?.errors && typeof problem.errors === 'object') {
      const messages = Object.values(problem.errors as Record<string, string[]>).flat();
      if (messages.length > 0) {
        return messages.join(' ');
      }
    }

    if (typeof problem?.title === 'string') {
      return problem.title;
    }
  } catch {
    // Not JSON — fall through to the status line.
  }

  return `Request failed (${response.status}).`;
}
