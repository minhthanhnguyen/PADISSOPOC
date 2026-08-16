import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

const VERIFY_URL = import.meta.env.VITE_VERIFY_MAGIC_LINK_URL as string | undefined;

type Tokens = {
  idToken?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
};

type Status =
  | { phase: 'idle' }
  | { phase: 'verifying' }
  | { phase: 'done'; tokens: Tokens }
  | { phase: 'failed'; message: string };

/** Decodes a JWT payload for display. No signature check — presentation only. */
function decodeClaims(jwt?: string): Record<string, unknown> | null {
  if (!jwt) return null;
  try {
    const payload = jwt.split('.')[1];
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export default function MagicLinkLanding() {
  const [params] = useSearchParams();
  const token = params.get('token');
  const [status, setStatus] = useState<Status>({ phase: 'idle' });

  // The token is single-use. StrictMode double-invokes effects in development,
  // and without this guard the second call consumes nothing and reports 401.
  const attempted = useRef(false);

  useEffect(() => {
    if (attempted.current) return;
    attempted.current = true;

    if (!token) {
      setStatus({ phase: 'failed', message: 'No token in the URL. This page expects ?token=…' });
      return;
    }
    if (!VERIFY_URL) {
      setStatus({ phase: 'failed', message: 'VITE_VERIFY_MAGIC_LINK_URL is not set.' });
      return;
    }

    setStatus({ phase: 'verifying' });
    void (async () => {
      try {
        const res = await fetch(VERIFY_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
        setStatus({ phase: 'done', tokens: body as Tokens });
      } catch (err) {
        setStatus({ phase: 'failed', message: err instanceof Error ? err.message : String(err) });
      }
    })();
  }, [token]);

  if (status.phase === 'idle' || status.phase === 'verifying') {
    return (
      <main className="card">
        <h2>Signing you in…</h2>
        <p className="muted">Redeeming your magic link.</p>
      </main>
    );
  }

  if (status.phase === 'failed') {
    return (
      <main className="card">
        <h2>That link didn&apos;t work</h2>
        <p className="error">{status.message}</p>
        <p className="muted">
          Magic links are single-use and expire after 15 minutes.{' '}
          <Link to="/magic-link">Request a new one</Link>.
        </p>
      </main>
    );
  }

  const claims = decodeClaims(status.tokens.idToken);
  const who = (claims?.['cognito:username'] ?? claims?.sub ?? 'you') as string;

  return (
    <main className="card wide">
      <h2>Signed in as {who}</h2>
      <p className="muted">
        Placeholder landing page. The tokens below came back from the verify endpoint, not from an
        Amplify session — a real application would persist them here and hydrate its own session.
      </p>

      {claims && (
        <table className="claims">
          <tbody>
            <tr><th>sub</th><td>{String(claims.sub ?? '—')}</td></tr>
            <tr><th>email</th><td>{String(claims.email ?? '—')}</td></tr>
            <tr><th>given_name</th><td>{String(claims.given_name ?? '—')}</td></tr>
            <tr><th>family_name</th><td>{String(claims.family_name ?? '—')}</td></tr>
            <tr><th>custom:last_login</th><td>{String(claims['custom:last_login'] ?? '—')}</td></tr>
            <tr>
              <th>expires</th>
              <td>
                {typeof claims.exp === 'number'
                  ? new Date(claims.exp * 1000).toLocaleString()
                  : '—'}
              </td>
            </tr>
          </tbody>
        </table>
      )}

      <section className="token">
        <div className="token-head"><h3>Endpoint response</h3></div>
        <pre>{JSON.stringify(status.tokens, null, 2)}</pre>
      </section>

      {claims && (
        <details>
          <summary>All ID token claims</summary>
          <pre>{JSON.stringify(claims, null, 2)}</pre>
        </details>
      )}

      <p className="muted">
        <Link to="/magic-link">Request another link</Link> · <Link to="/login">Password sign-in</Link>
      </p>
    </main>
  );
}
