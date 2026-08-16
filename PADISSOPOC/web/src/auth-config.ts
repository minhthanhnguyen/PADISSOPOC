import { Amplify } from 'aws-amplify';

const userPoolId = import.meta.env.VITE_USER_POOL_ID;
const userPoolClientId = import.meta.env.VITE_USER_POOL_CLIENT_ID;

if (!userPoolId || !userPoolClientId) {
  throw new Error(
    'Missing VITE_USER_POOL_ID or VITE_USER_POOL_CLIENT_ID. Copy web/.env.example to web/.env.local and fill in the stack outputs.',
  );
}

Amplify.configure({
  Auth: {
    Cognito: {
      userPoolId,
      userPoolClientId,
      // The pool signs in by username only — email and phone are not aliases.
      loginWith: { username: true, email: false, phone: false },
    },
  },
});

/** Mirrors the pool's PasswordPolicy, for client-side hinting only. */
export const PASSWORD_RULES = 'At least 6 characters, with one uppercase and one lowercase letter.';
