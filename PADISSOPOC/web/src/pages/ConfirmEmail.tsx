import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  confirmRegistration,
  resendRegistrationCode,
  resendRegistrationCodeByUsername,
} from '../api-client';
import { forgetAccountId, recallAccountId } from '../pending-signup';

// A code can be resent from any browser, but confirming still needs the account id, which
// only the browser that signed up holds.
const UNKNOWN_ACCOUNT =
  'This browser did not start that sign-up, so the code cannot be entered here. Enter it in ' +
  'the browser you signed up in, or sign up again here — the name is still available.';

export default function ConfirmEmail() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  // The account id is the opaque Cognito username. It arrives in the URL straight after
  // sign-up; otherwise the user types the name they chose and it is looked up locally.
  const [accountId, setAccountId] = useState(params.get('username') ?? '');
  const [chosenName, setChosenName] = useState(params.get('as') ?? '');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  /** Resolves the id to act on, falling back to a lookup by the name the user typed. */
  function resolveAccountId(): string | null {
    if (accountId) {
      return accountId;
    }
    const recalled = recallAccountId(chosenName);
    if (recalled) {
      setAccountId(recalled);
      return recalled;
    }
    setError(UNKNOWN_ACCOUNT);
    return null;
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);

    const id = resolveAccountId();
    if (!id) {
      return;
    }

    setBusy(true);
    try {
      // The API answers 204 on success and raises ApiError otherwise, so reaching the next
      // line means the account is confirmed — there is no partial-success state to check.
      await confirmRegistration(id, code.trim());

      // The PostConfirmation trigger has now assigned preferred_username, so the chosen
      // name works as a sign-in alias from here and the id is no longer needed.
      forgetAccountId(chosenName);
      navigate('/login?confirmed=1');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onResend() {
    setError(null);
    setNotice(null);

    // Prefer the id when this browser has one. Without it, resend by name and let the API
    // find the pending sign-up — no dead end just because the id was never stored here.
    const id = accountId || recallAccountId(chosenName);
    if (id && !accountId) {
      setAccountId(id);
    }

    try {
      if (id) {
        const { codeDestination } = await resendRegistrationCode(id);
        setNotice(
          codeDestination
            ? `A new code is on its way to ${codeDestination}.`
            : 'A new code is on its way.',
        );
        return;
      }

      // The API answers the same whether or not a sign-up is pending under the name, so the
      // notice must not claim one is.
      await resendRegistrationCodeByUsername(chosenName.trim());
      setNotice(
        'If a sign-up is waiting under that name, a new code is on its way. Enter it in the ' +
          'browser you signed up in.',
      );
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
          <input
            value={chosenName}
            onChange={(e) => {
              setChosenName(e.target.value);
              // A different name invalidates an id carried over from the URL.
              setAccountId('');
            }}
            autoComplete="username"
            required
          />
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
        <button type="button" className="linkish" onClick={onResend} disabled={!chosenName}>
          Resend code
        </button>
      </p>
    </main>
  );
}
