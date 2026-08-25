import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { confirmResetPassword, resetPassword } from 'aws-amplify/auth';
import { PASSWORD_RULES } from '../auth-config';

type Stage = 'request' | 'confirm';

export default function ForgotPassword() {
  const navigate = useNavigate();

  const [stage, setStage] = useState<Stage>('request');
  const [username, setUsername] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [destination, setDestination] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onRequest(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const { nextStep } = await resetPassword({ username: username.trim() });

      if (nextStep.resetPasswordStep === 'CONFIRM_RESET_PASSWORD_WITH_CODE') {
        setDestination(nextStep.codeDeliveryDetails?.destination ?? null);
        setStage('confirm');
        return;
      }

      // 'DONE' means Cognito considers the reset already complete.
      navigate('/login?reset=1');
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

    if (password !== confirmPassword) {
      setError('The two passwords do not match.');
      return;
    }

    setBusy(true);
    try {
      await confirmResetPassword({
        username: username.trim(),
        confirmationCode: code.trim(),
        newPassword: password,
      });
      navigate('/login?reset=1');
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
      const { nextStep } = await resetPassword({ username: username.trim() });
      setDestination(nextStep.codeDeliveryDetails?.destination ?? destination);
      setNotice('A new code is on its way.');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <main className="card">
      <h2>Reset your password</h2>

      {stage === 'request' && (
        <>
          <p className="muted">
            Enter your username and Cognito emails a reset code to the address on the account.
          </p>

          <form onSubmit={onRequest}>
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

            {error && <p className="error">{error}</p>}

            <button type="submit" disabled={busy}>
              {busy ? 'Sending code…' : 'Send reset code'}
            </button>
          </form>
        </>
      )}

      {stage === 'confirm' && (
        <>
          <p className="notice">
            {destination
              ? <>A reset code is on its way to <code>{destination}</code></>
              : <>If that account exists, a reset code is on its way.</>}
          </p>

          <form onSubmit={onConfirm}>
            <label>
              Reset code
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                required
              />
            </label>

            <label>
              New password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
              <small className="muted">{PASSWORD_RULES}</small>
            </label>

            <label>
              Confirm new password
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
            </label>

            {error && <p className="error">{error}</p>}
            {notice && <p className="notice">{notice}</p>}

            <button type="submit" disabled={busy}>
              {busy ? 'Resetting…' : 'Set new password'}
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
                setStage('request');
                setCode('');
                setPassword('');
                setConfirmPassword('');
                setDestination(null);
                setError(null);
                setNotice(null);
              }}
            >
              Start over
            </button>
          </p>
        </>
      )}

      <p className="muted">
        Remembered it? <Link to="/login">Back to sign in</Link>
      </p>
    </main>
  );
}
