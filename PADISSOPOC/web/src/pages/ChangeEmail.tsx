import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  confirmUserAttribute,
  fetchAuthSession,
  fetchUserAttributes,
  sendUserAttributeVerificationCode,
  updateUserAttributes,
} from 'aws-amplify/auth';

type Stage = 'loading' | 'enter-email' | 'enter-code' | 'done';

export default function ChangeEmail() {
  const navigate = useNavigate();

  const [stage, setStage] = useState<Stage>('loading');
  const [currentEmail, setCurrentEmail] = useState<string | null>(null);
  const [verified, setVerified] = useState<boolean>(false);
  const [newEmail, setNewEmail] = useState('');
  const [code, setCode] = useState('');
  // Masked address Cognito says it sent the code to — the only signal the client
  // gets about whether delivery went to the new address or the old one.
  const [destination, setDestination] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadAttributes = useCallback(async () => {
    try {
      const attrs = await fetchUserAttributes();
      setCurrentEmail(attrs.email ?? null);
      setVerified(attrs.email_verified === 'true');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void loadAttributes().then(() => {
      setStage((s) => (s === 'loading' ? 'enter-email' : s));
    });
  }, [loadAttributes]);

  async function onRequestChange(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);

    const target = newEmail.trim();
    if (target.toLowerCase() === (currentEmail ?? '').toLowerCase()) {
      setError('That is already the address on the account.');
      return;
    }

    setBusy(true);
    try {
      const result = await updateUserAttributes({ userAttributes: { email: target } });
      const step = result.email?.nextStep;

      if (step?.updateAttributeStep === 'CONFIRM_ATTRIBUTE_WITH_CODE') {
        setDestination(step.codeDeliveryDetails?.destination ?? null);
        setStage('enter-code');
        return;
      }

      // Only reachable if verification-before-update is off for the pool, in which
      // case Cognito has already swapped the address.
      await refreshSession();
      setStage('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onConfirm(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await confirmUserAttribute({
        userAttributeKey: 'email',
        confirmationCode: code.trim(),
      });
      await refreshSession();
      setStage('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onResend() {
    setError(null);
    setNotice(null);
    try {
      const details = await sendUserAttributeVerificationCode({ userAttributeKey: 'email' });
      setDestination(details.destination ?? destination);
      setNotice('A new code is on its way.');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  /** The ID token caches the old email claim until the session is refreshed. */
  async function refreshSession() {
    await fetchAuthSession({ forceRefresh: true });
    await loadAttributes();
  }

  if (stage === 'loading') {
    return <main className="card"><p className="muted">Loading account…</p></main>;
  }

  return (
    <main className="card">
      <h2>Change email address</h2>

      <table className="claims">
        <tbody>
          <tr><th>Current email</th><td>{currentEmail ?? '—'}</td></tr>
          <tr><th>Verified</th><td>{String(verified)}</td></tr>
        </tbody>
      </table>

      {stage === 'enter-email' && (
        <>
          <p className="muted">
            The pool keeps the current address active until the new one is verified, so sign-in and
            account recovery keep working throughout.
          </p>

          <form onSubmit={onRequestChange}>
            <label>
              New email address
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                autoComplete="email"
                placeholder="you@example.com"
                required
              />
            </label>

            {error && <p className="error">{error}</p>}

            <button type="submit" disabled={busy}>
              {busy ? 'Sending code…' : 'Send verification code'}
            </button>
          </form>
        </>
      )}

      {stage === 'enter-code' && (
        <>
          <p className="notice">
            Cognito sent a code to <code>{destination ?? 'the address on file'}</code>.
          </p>
          <p className="muted">
            Requested change to <code>{newEmail}</code>. It does not take effect until the code below
            is accepted.
          </p>

          <form onSubmit={onConfirm}>
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
            {notice && <p className="notice">{notice}</p>}

            <button type="submit" disabled={busy}>
              {busy ? 'Verifying…' : 'Confirm new email'}
            </button>
          </form>

          <p className="muted">
            Didn&apos;t get it?{' '}
            <button type="button" className="linkish" onClick={onResend}>
              Resend code
            </button>
            {' · '}
            <button
              type="button"
              className="linkish"
              onClick={() => {
                setStage('enter-email');
                setCode('');
                setDestination(null);
                setError(null);
                setNotice(null);
              }}
            >
              Use a different address
            </button>
          </p>
        </>
      )}

      {stage === 'done' && (
        <>
          <p className="notice">Email address updated.</p>
          <button type="button" onClick={() => navigate('/')}>Back to dashboard</button>
        </>
      )}

      {stage !== 'done' && (
        <p className="muted">
          <button type="button" className="linkish" onClick={() => navigate('/')}>
            Back to dashboard
          </button>
        </p>
      )}
    </main>
  );
}
