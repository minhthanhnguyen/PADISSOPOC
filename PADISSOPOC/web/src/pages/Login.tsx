import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { signIn } from 'aws-amplify/auth';

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
      // USER_SRP_AUTH: the pool's app client has USER_PASSWORD_AUTH disabled,
      // so the password is never sent to Cognito in plaintext.
      const { isSignedIn, nextStep } = await signIn({
        username,
        password,
        options: { authFlowType: 'USER_SRP_AUTH' },
      });

      if (isSignedIn) {
        navigate('/');
        return;
      }

      if (nextStep.signInStep === 'CONFIRM_SIGN_UP') {
        navigate(`/confirm?username=${encodeURIComponent(username)}`);
        return;
      }

      setError(`Additional step required: ${nextStep.signInStep}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="card">
      <h2>Sign in</h2>
      {params.get('confirmed') && <p className="notice">Email verified. You can sign in now.</p>}

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
        No account yet? <Link to="/signup">Create one</Link>
      </p>
      <p className="muted">
        Or sign in <Link to="/passwordless">without a password</Link> ·{' '}
        <Link to="/magic-link">magic link</Link>
      </p>
    </main>
  );
}
