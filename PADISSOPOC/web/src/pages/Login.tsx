import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, login } from '../api-client';
import { saveSession } from '../session';

export default function Login() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      // Sign-in goes through the management API, which runs ADMIN_USER_PASSWORD_AUTH under
      // its own IAM role. The app client keeps USER_PASSWORD_AUTH disabled, so this flow
      // cannot be reproduced against Cognito directly — it only works through the API.
      const tokens = await login(username, password);

      // Bridged into Amplify by the token provider in auth-config.ts, so the rest of the
      // app sees a normal session.
      saveSession(tokens);
      navigate('/');
    } catch (err) {
      // 403 means the password was right but the account was never confirmed. Send the
      // user to finish that rather than showing a dead end.
      if (err instanceof ApiError && err.status === 403) {
        navigate(`/confirm?as=${encodeURIComponent(username)}`);
        return;
      }

      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="card">
      <h2>Sign in</h2>
      {params.get('confirmed') && <p className="notice">Email verified. You can sign in now.</p>}
      {params.get('reset') && <p className="notice">Password reset. Sign in with your new password.</p>}

      <form onSubmit={onSubmit}>
        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
          <small className="muted">Usernames are not case-sensitive.</small>
        </label>

        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        {error && <p className="error">{error}</p>}

        <button type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <p className="muted">
        <Link to="/forgot-password">Forgot your password?</Link>
      </p>
      <p className="muted">
        No account yet? <Link to="/signup">Create one</Link>
      </p>
      <p className="muted">
        Or sign in <Link to="/passwordless">without a password</Link> ·{' '}
        <Link to="/magic-link">magic link</Link>
      </p>
    </main>
  );
}
