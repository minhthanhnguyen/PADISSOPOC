import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { answerChallenge, startChallenge, type PasswordlessFactor } from '../api-client';
import { saveSession } from '../session';
import { signWithPasskey } from '../webauthn';

const FACTORS: { id: PasswordlessFactor; label: string; blurb: string }[] = [
  { id: 'EMAIL_OTP', label: 'Email code', blurb: 'A 6-digit code is emailed to you.' },
  { id: 'SMS_OTP', label: 'SMS code', blurb: 'Requires a verified phone number on the account.' },
  { id: 'WEB_AUTHN', label: 'Passkey', blurb: 'Requires a passkey registered for this site.' },
];

type Pending = { session: string; destination: string | null };

export default function PasswordlessLogin() {
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [factor, setFactor] = useState<PasswordlessFactor>('EMAIL_OTP');
  const [pending, setPending] = useState<Pending | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Every step goes through the management API: it relays Cognito's challenge on a
  // server-side client, so the browser never calls Cognito's sign-in operations. For a
  // passkey the browser only runs the WebAuthn ceremony, which has to happen on this device.
  async function start(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const name = username.trim();
      const challenge = await startChallenge(name, factor);

      if (factor === 'WEB_AUTHN') {
        if (!challenge.credentialRequestOptions) {
          throw new Error('The sign-in service returned no passkey options.');
        }
        const assertion = await signWithPasskey(challenge.credentialRequestOptions);
        await finish(name, challenge.session, assertion);
        return;
      }

      setPending({ session: challenge.session, destination: challenge.codeDestination });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    if (!pending) return;
    setError(null);
    setBusy(true);
    try {
      await finish(username.trim(), pending.session, code.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function finish(name: string, session: string, answer: string) {
    saveSession(await answerChallenge(name, factor, session, answer));
    navigate('/');
  }

  function startOver() {
    setPending(null);
    setCode('');
    setError(null);
  }

  return (
    <main className="card">
      <h2>Passwordless sign-in</h2>
      <p className="muted">
        One-time codes and passkeys, relayed through the PADI API — this page never calls Cognito&apos;s
        sign-in directly.
      </p>

      {!pending ? (
        <form onSubmit={start}>
          <label>
            Username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username webauthn"
              required
            />
          </label>

          <fieldset>
            <legend>Sign in with</legend>
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

          <button type="submit" disabled={busy}>
            {busy ? 'Starting…' : 'Continue'}
          </button>
        </form>
      ) : (
        <form onSubmit={submitCode}>
          <p className="notice">
            A code is on its way{pending.destination ? <> to <code>{pending.destination}</code></> : null}.
          </p>
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
          <button type="button" className="linkish" onClick={startOver}>
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
