import { Amplify } from 'aws-amplify';
import { decodeJWT } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { loadSession } from './session';

const userPoolId = import.meta.env.VITE_USER_POOL_ID;
const userPoolClientId = import.meta.env.VITE_USER_POOL_CLIENT_ID;

if (!userPoolId || !userPoolClientId) {
  throw new Error(
    'Missing VITE_USER_POOL_ID or VITE_USER_POOL_CLIENT_ID. Copy web/.env.example to web/.env.local and fill in the stack outputs.',
  );
}

Amplify.configure(
  {
    Auth: {
      Cognito: {
        userPoolId,
        userPoolClientId,
        // The pool signs in by username only — email and phone are not aliases.
        loginWith: { username: true, email: false, phone: false },
      },
    },
  },
  {
    Auth: {
      // Sign-in happens two ways: Amplify's own SRP flow, and the management API's
      // /public/login, which hands back tokens Amplify knows nothing about. Rather than run
      // two parallel sessions — which would leave the profile pages and passkeys working
      // only for SRP — this provider prefers the API's tokens when present and otherwise
      // defers to Amplify's own store. Downstream code stays unaware of the difference.
      tokenProvider: {
        async getTokens(options) {
          const session = loadSession();
          if (session) {
            return {
              accessToken: decodeJWT(session.accessToken),
              idToken: decodeJWT(session.idToken),
            };
          }

          return cognitoUserPoolsTokenProvider.getTokens(options);
        },
      },
    },
  },
);

/** Mirrors the pool's PasswordPolicy, for client-side hinting only. */
export const PASSWORD_RULES = 'At least 6 characters, with one uppercase and one lowercase letter.';
