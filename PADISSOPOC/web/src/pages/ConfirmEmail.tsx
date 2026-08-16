import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { confirmSignUp, resendSignUpCode } from 'aws-amplify/auth';

export default function ConfirmEmail() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [username, setUsername] = useState(params.get('username') ?? '');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const { isSignUpComplete } = await confirmSignUp({
        username,
        confirmationCode: code.trim(),
      });
      if (isSignUpComplete) {
        navigate('/login?confirmed=1');
      } else {
        setError('Confirmation did not complete. Check the code and try again.');
      }
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
      await resendSignUpCode({ username });
      setNotice('A new code is on its way.');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <main className="card">
      <h2>Verify your email</h2>
      <p className="muted">
        Cognito emailed a 6-digit code to the address on the account. The account stays unconfirmed —
        and sign-in will fail — until the code is entered.
      </p>

      <form onSubmit={onSubmit}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>

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
          {busy ? 'Verifying…' : 'Confirm account'}
        </button>
      </form>

      <p className="muted">
        Didn&apos;t get it?{' '}
        <button type="button" className="linkish" onClick={onResend} disabled={!username}>
          Resend code
        </button>
      </p>
    </main>
  );
}
