import { useEffect, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

const REQUEST_URL = import.meta.env.VITE_REQUEST_MAGIC_LINK_URL as string | undefined;
const VERIFY_URL = import.meta.env.VITE_VERIFY_MAGIC_LINK_URL as string | undefined;

type Tokens = {
  idToken?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
};

export default function MagicLink() {
  const [params] = useSearchParams();

  const [username, setUsername] = useState('');
  const [channel, setChannel] = useState<'email' | 'sms'>('email');
  const [token, setToken] = useState(params.get('token') ?? '');
  const [tokens, setTokens] = useState<Tokens | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // A link opened directly at /magic-link?token=… should be usable as-is.
  useEffect(() => {
    const t = params.get('token');
    if (t) setToken(t);
  }, [params]);

  async function request(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (!REQUEST_URL) {
      setError('VITE_REQUEST_MAGIC_LINK_URL is not set. Add the RequestMagicLinkUrl stack output to .env.local.');
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(REQUEST_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, channel }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setNotice(
        'Request accepted. If the account exists and has that contact method, a link is on its way. ' +
          'The endpoint always reports success, so this is not confirmation the account exists.',
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (!VERIFY_URL) {
      setError('VITE_VERIFY_MAGIC_LINK_URL is not set.');
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(VERIFY_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: token.trim() }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
      setTokens(body as Tokens);
      setNotice('Token accepted.');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="card wide">
      <h2>Magic link</h2>
      <p className="muted">
        Calls the Lambda Function URLs directly. Tokens are returned by the endpoint rather than held
        in an Amplify session, so this page shows them inline instead of redirecting.
      </p>

      <form onSubmit={request}>
        <h3>1 — Request a link</h3>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </label>
        <fieldset>
          <legend>Channel</legend>
          <label className="radio">
            <input type="radio" checked={channel === 'email'} onChange={() => setChannel('email')} />
            <span>Email</span>
          </label>
          <label className="radio">
            <input type="radio" checked={channel === 'sms'} onChange={() => setChannel('sms')} />
            <span>SMS<small className="muted"> — needs phone_number and SNS production access</small></span>
          </label>
        </fieldset>
        <button type="submit" disabled={busy || !username}>
          {busy ? 'Sending…' : 'Send link'}
        </button>
      </form>

      <form onSubmit={verify} style={{ marginTop: '1.5rem' }}>
        <h3>2 — Redeem manually (fallback)</h3>
        <p className="muted">
          Normally you just click the emailed link, which lands on <code>/verify</code> and redeems
          automatically. Use this only when <code>magicLinkBaseUrl</code> points somewhere other than
          this app — paste the <code>token</code> query parameter from the link.
        </p>
        <label>
          Token
          <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="64-character hex" />
        </label>
        <button type="submit" disabled={busy || !token}>
          {busy ? 'Verifying…' : 'Redeem'}
        </button>
      </form>

      {error && <p className="error" style={{ marginTop: '1rem' }}>{error}</p>}
      {notice && <p className="notice" style={{ marginTop: '1rem' }}>{notice}</p>}

      {tokens && (
        <section className="token">
          <div className="token-head"><h3>Returned tokens</h3></div>
          <pre>{JSON.stringify(tokens, null, 2)}</pre>
        </section>
      )}

      <p className="muted">
        <Link to="/login">Password sign-in</Link> · <Link to="/passwordless">Passwordless</Link>
      </p>
    </main>
  );
}
