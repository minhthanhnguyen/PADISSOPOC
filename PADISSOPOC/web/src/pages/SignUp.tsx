import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { signUp } from 'aws-amplify/auth';
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

    // signUp cannot catch a bad name: the account's username is a UUID, so the request
    // succeeds regardless and the problem only surfaces once PostConfirmation promotes
    // the staged value into the alias.
    const usernameProblem = validateUsername(form.username.trim());
    if (usernameProblem) {
      setError(usernameProblem);
      return;
    }

    setBusy(true);
    try {
      // Cognito's username is immutable, so it cannot be the name the user picked — that
      // name has to stay changeable. The account gets an opaque id the user never sees,
      // and the chosen name is parked in custom:signup_username for the PostConfirmation
      // trigger to promote into preferred_username, the alias they sign in with.
      const accountId = crypto.randomUUID();
      const chosen = form.username.trim();

      const { nextStep } = await signUp({
        username: accountId,
        password: form.password,
        options: {
          userAttributes: {
            email: form.email,
            given_name: form.givenName,
            family_name: form.familyName,
            'custom:signup_username': chosen,
          },
        },
      });

      // Until the account is confirmed the alias does not exist, so this id is the only
      // way to reach it. Remembered here so a reload of /confirm can recover.
      rememberAccountId(chosen, accountId);

      if (nextStep.signUpStep === 'CONFIRM_SIGN_UP') {
        navigate(`/confirm?username=${encodeURIComponent(accountId)}&as=${encodeURIComponent(chosen)}`);
      } else {
        // No confirmation required (auto-confirmed) — go straight to sign-in.
        navigate('/login');
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
