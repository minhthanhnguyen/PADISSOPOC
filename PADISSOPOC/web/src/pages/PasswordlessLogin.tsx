import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { confirmSignIn, signIn } from 'aws-amplify/auth';

type Factor = 'EMAIL_OTP' | 'SMS_OTP' | 'WEB_AUTHN';

const FACTORS: { id: Factor; label: string; blurb: string }[] = [
  { id: 'EMAIL_OTP', label: 'Email code', blurb: 'Cognito emails a 6-digit code.' },
  { id: 'SMS_OTP', label: 'SMS code', blurb: 'Requires a verified phone_number on the account.' },
  { id: 'WEB_AUTHN', label: 'Passkey', blurb: 'Requires a passkey registered for this relying party.' },
];

export default function PasswordlessLogin() {
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [factor, setFactor] = useState<Factor>('EMAIL_OTP');
  const [awaitingCode, setAwaitingCode] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function startSignIn(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const { isSignedIn, nextStep } = await signIn({
        username,
        options: { authFlowType: 'USER_AUTH', preferredChallenge: factor },
      });

      if (isSignedIn) {
        navigate('/');
        return;
      }

      switch (nextStep.signInStep) {
        case 'CONFIRM_SIGN_IN_WITH_EMAIL_CODE':
          setAwaitingCode(true);
          setNotice('Code sent by email.');
          break;
        case 'CONFIRM_SIGN_IN_WITH_SMS_CODE':
          setAwaitingCode(true);
          setNotice('Code sent by SMS.');
          break;
        case 'CONTINUE_SIGN_IN_WITH_FIRST_FACTOR_SELECTION':
          setError(
            `Cognito would not honour ${factor}. Available: ${
              nextStep.availableChallenges?.join(', ') ?? 'none reported'
            }`,
          );
          break;
        default:
          setError(`Unhandled next step: ${nextStep.signInStep}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { isSignedIn, nextStep } = await confirmSignIn({ challengeResponse: code.trim() });
      if (isSignedIn) navigate('/');
      else setError(`Unhandled next step: ${nextStep.signInStep}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="card">
      <h2>Passwordless sign-in</h2>
      <p className="muted">
        Uses Cognito&apos;s choice-based <code>USER_AUTH</code> flow with an explicit first factor.
      </p>

      {!awaitingCode ? (
        <form onSubmit={startSignIn}>
          <label>
            Username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>

          <fieldset>
            <legend>First factor</legend>
            {FACTORS.map((f) => (
              <label key={f.id} className="radio">
                <input
                  type="radio"
                  name="factor"
                  value={f.id}
                  checked={factor === f.id}
                  onChange={() => setFactor(f.id)}
                />
                <span>
                  {f.label}
                  <small className="muted"> — {f.blurb}</small>
                </span>
              </label>
            ))}
          </fieldset>

          {error && <p className="error">{error}</p>}
          {notice && <p className="notice">{notice}</p>}

          <button type="submit" disabled={busy}>
            {busy ? 'Starting…' : 'Continue'}
          </button>
        </form>
      ) : (
        <form onSubmit={submitCode}>
          {notice && <p className="notice">{notice}</p>}
          <label>
            Verification code
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              required
            />
          </label>

          {error && <p className="error">{error}</p>}

          <button type="submit" disabled={busy}>
            {busy ? 'Verifying…' : 'Sign in'}
          </button>
          <button
            type="button"
            className="linkish"
            onClick={() => {
              setAwaitingCode(false);
              setCode('');
              setError(null);
              setNotice(null);
            }}
          >
            Start over
          </button>
        </form>
      )}

      <p className="muted">
        <Link to="/login">Password sign-in</Link> · <Link to="/magic-link">Magic link</Link>
      </p>
    </main>
  );
}
