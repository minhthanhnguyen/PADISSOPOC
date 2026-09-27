import { Amplify } from 'aws-amplify';
import { decodeJWT } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { currentSession } from './session';

const userPoolId = import.meta.env.VITE_USER_POOL_ID;
const userPoolClientId = import.meta.env.VITE_USER_POOL_CLIENT_ID;

if (!userPoolId || !userPoolClientId) {
  throw new Error(
    'Missing VITE_USER_POOL_ID or VITE_USER_POOL_CLIENT_ID. Copy web/.env.example to web/.env.local and fill in the stack outputs.',
  );
}

const authConfig = {
  Cognito: {
    userPoolId,
    userPoolClientId,
    // The pool signs in by username only — email and phone are not aliases.
    loginWith: { username: true, email: false, phone: false },
  },
};

Amplify.configure(
  { Auth: authConfig },
  {
    Auth: {
      // Amplify never signs anyone in: every sign-in goes through the API, which issues
      // tokens from a server-side client with a secret. Amplify is kept for the calls a
      // signed-in user makes with their own access token — reading and updating attributes,
      // managing passkeys — and this provider hands it the API's tokens, refreshing them
      // through the API when needed.
      tokenProvider: {
        async getTokens(options) {
          const session = await currentSession(options?.forceRefresh ?? false);
          return session
            ? { accessToken: decodeJWT(session.accessToken), idToken: decodeJWT(session.idToken) }
            : null;
        },
      },
    },
  },
);

// Amplify's own token store must be configured even though it holds nothing: some Amplify
// calls, sign-out among them, touch it and throw "Auth UserPool not configured" otherwise.
// Supplying a custom tokenProvider skips this configuration step.
cognitoUserPoolsTokenProvider.setAuthConfig(authConfig);

/** Mirrors the pool's PasswordPolicy, for client-side hinting only. */
export const PASSWORD_RULES = 'At least 12 characters, with one uppercase and one lowercase letter.';
