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
    middleInitial: '',
    familyName: '',
    birthdate: '',
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
        middleInitial: form.middleInitial,
        familyName: form.familyName,
        birthdate: form.birthdate,
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

        {/* None of these is required — they are optional attributes on the pool, so the
            form must not insist on them. Leaving one blank stores nothing. */}
        {/* Two per row: .row gives each label flex: 1 with no min-width override, so a
            third field overflows the card rather than shrinking. */}
        <div className="row">
          <label>
            First name
            <input value={form.givenName} onChange={set('givenName')} autoComplete="given-name" />
          </label>
          <label>
            Last name
            <input value={form.familyName} onChange={set('familyName')} autoComplete="family-name" />
          </label>
        </div>

        <div className="row">
          <label>
            Middle initial
            <input
              value={form.middleInitial}
              onChange={set('middleInitial')}
              maxLength={1}
              autoComplete="additional-name"
            />
          </label>
          <label>
            Date of birth
            {/* type=date yields YYYY-MM-DD, the only format Cognito's birthdate accepts. */}
            <input type="date" value={form.birthdate} onChange={set('birthdate')} autoComplete="bday" />
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
