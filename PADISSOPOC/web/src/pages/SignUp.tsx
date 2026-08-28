import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { registerAccount } from '../api-client';
import { PASSWORD_RULES } from '../auth-config';
import { rememberAccountId } from '../pending-signup';
import { USERNAME_RULES, validateUsername } from '../username-rules';

export default function SignUp() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    username: '',
    password: '',
    email: '',
    givenName: '',
    familyName: '',
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (k: keyof typeof form) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    // The API validates this too; checking here saves a round trip and reports the same
    // message, since both sides share the rule.
    const usernameProblem = validateUsername(form.username.trim());
    if (usernameProblem) {
      setError(usernameProblem);
      return;
    }

    setBusy(true);
    try {
      const chosen = form.username.trim();

      // Registration goes through the management API rather than Cognito directly. The
      // opaque account id is minted server-side, so the browser no longer needs to know
      // that the chosen name is staged in custom:signup_username for the PostConfirmation
      // trigger — it just receives the id needed to confirm.
      const result = await registerAccount({
        username: chosen,
        password: form.password,
        email: form.email,
        givenName: form.givenName,
        familyName: form.familyName,
      });

      // Until the account is confirmed the alias does not exist, so this id is the only
      // way to reach it. Remembered here so a reload of /confirm can recover.
      rememberAccountId(chosen, result.accountId);

      if (result.confirmed) {
        // Auto-confirmed — no code to enter.
        navigate('/login');
      } else {
        navigate(`/confirm?username=${encodeURIComponent(result.accountId)}&as=${encodeURIComponent(chosen)}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="card">
      <h2>Create an account</h2>

      <form onSubmit={onSubmit}>
        <label>
          Username
          <input value={form.username} onChange={set('username')} autoComplete="username" required />
          <small className="muted">You can change this later. {USERNAME_RULES}</small>
        </label>

        <div className="row">
          <label>
            First name
            <input value={form.givenName} onChange={set('givenName')} autoComplete="given-name" required />
          </label>
          <label>
            Last name
            <input value={form.familyName} onChange={set('familyName')} autoComplete="family-name" required />
          </label>
        </div>

        <label>
          Email
          <input type="email" value={form.email} onChange={set('email')} autoComplete="email" required />
        </label>

        <label>
          Password
          <input
            type="password"
            value={form.password}
            onChange={set('password')}
            autoComplete="new-password"
            required
          />
          <small className="muted">{PASSWORD_RULES}</small>
        </label>

        {error && <p className="error">{error}</p>}

        <button type="submit" disabled={busy}>
          {busy ? 'Creating account…' : 'Sign up'}
        </button>
      </form>

      <p className="muted">
        Already registered? <Link to="/login">Sign in</Link>
      </p>
    </main>
  );
}
