import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchAuthSession, getCurrentUser, signOut } from 'aws-amplify/auth';
import Passkeys from '../components/Passkeys';

type Tokens = {
  username: string;
  idToken: string;
  accessToken: string;
  claims: Record<string, unknown>;
};

function TokenBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <section className="token">
      <div className="token-head">
        <h3>{label}</h3>
        <button type="button" className="linkish" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre>{value}</pre>
    </section>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [tokens, setTokens] = useState<Tokens | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [user, session] = await Promise.all([getCurrentUser(), fetchAuthSession()]);
      const idToken = session.tokens?.idToken;
      const accessToken = session.tokens?.accessToken;

      if (!idToken || !accessToken) {
        setError('No tokens on the current session.');
        return;
      }

      setTokens({
        username: user.username,
        idToken: idToken.toString(),
        accessToken: accessToken.toString(),
        claims: idToken.payload as Record<string, unknown>,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onSignOut() {
    await signOut();
    navigate('/login');
  }

  if (error) {
    return (
      <main className="card">
        <p className="error">{error}</p>
        <button type="button" onClick={onSignOut}>Sign out</button>
      </main>
    );
  }

  if (!tokens) {
    return <main className="card"><p className="muted">Loading session…</p></main>;
  }

  const claim = (k: string) => (tokens.claims[k] as string | undefined) ?? '—';
  const exp = tokens.claims.exp as number | undefined;

  return (
    <main className="card wide">
      <div className="token-head">
        <h2>Signed in as {tokens.username}</h2>
        <button type="button" onClick={onSignOut}>Sign out</button>
      </div>

      <table className="claims">
        <tbody>
          <tr><th>sub</th><td>{claim('sub')}</td></tr>
          <tr><th>email</th><td>{claim('email')}</td></tr>
          <tr><th>email_verified</th><td>{String(tokens.claims.email_verified ?? '—')}</td></tr>
          <tr><th>given_name</th><td>{claim('given_name')}</td></tr>
          <tr><th>family_name</th><td>{claim('family_name')}</td></tr>
          <tr><th>custom:last_login</th><td>{claim('custom:last_login')}</td></tr>
          <tr>
            <th>expires</th>
            <td>{exp ? new Date(exp * 1000).toLocaleString() : '—'}</td>
          </tr>
        </tbody>
      </table>

      <Passkeys />

      <TokenBlock label="ID token" value={tokens.idToken} />
      <TokenBlock label="Access token" value={tokens.accessToken} />

      <details>
        <summary>All ID token claims</summary>
        <pre>{JSON.stringify(tokens.claims, null, 2)}</pre>
      </details>
    </main>
  );
}
