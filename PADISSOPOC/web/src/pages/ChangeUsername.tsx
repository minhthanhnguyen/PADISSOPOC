import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchAuthSession, fetchUserAttributes, updateUserAttributes } from 'aws-amplify/auth';
import { USERNAME_RULES, validateUsername } from '../username-rules';

export default function ChangeUsername() {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [current, setCurrent] = useState<string | null>(null);
  const [next, setNext] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const attrs = await fetchUserAttributes();
      setCurrent(attrs.preferred_username ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);

    const target = next.trim();
    if (target.toLowerCase() === (current ?? '').toLowerCase()) {
      setError('That is already your username.');
      return;
    }

    // Cognito would accept an invalid alias on the attribute write and then reject it
    // everywhere the user types it, so this check is the only thing standing between the
    // user and a silently unusable account.
    const problem = validateUsername(target);
    if (problem) {
      setError(problem);
      return;
    }

    setBusy(true);
    try {
      // No verification step: preferred_username is not a contact attribute, so the
      // change is immediate. Cognito enforces uniqueness across the pool and rejects a
      // name already taken by another account.
      await updateUserAttributes({ userAttributes: { preferred_username: target } });

      // The id token carries preferred_username as a claim; without a refresh the app
      // keeps showing the old name.
      await fetchAuthSession({ forceRefresh: true });
      await load();

      setNext('');
      setNotice(`Signed-in name is now ${target}. Use it next time you sign in.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return <main className="card"><p className="muted">Loading account…</p></main>;
  }

  return (
    <main className="card">
      <h2>Change username</h2>

      <table className="claims">
        <tbody>
          <tr><th>Current username</th><td>{current ?? '—'}</td></tr>
        </tbody>
      </table>

      <p className="muted">
        This is the name you sign in with. Changing it releases the old one for anyone else to
        take, and takes effect immediately — there is no verification step.
      </p>

      <form onSubmit={onSubmit}>
        <label>
          New username
          <input
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="username"
            required
          />
          <small className="muted">
            {USERNAME_RULES} Not case-sensitive, and must not be taken by another account.
          </small>
        </label>

        {error && <p className="error">{error}</p>}
        {notice && <p className="notice">{notice}</p>}

        <button type="submit" disabled={busy}>
          {busy ? 'Updating…' : 'Change username'}
        </button>
      </form>

      <p className="muted">
        <button type="button" className="linkish" onClick={() => navigate('/')}>
          Back to dashboard
        </button>
      </p>
    </main>
  );
}
