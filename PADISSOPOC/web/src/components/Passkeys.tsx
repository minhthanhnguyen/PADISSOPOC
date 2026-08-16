import { useCallback, useEffect, useState } from 'react';
import {
  associateWebAuthnCredential,
  deleteWebAuthnCredential,
  listWebAuthnCredentials,
} from 'aws-amplify/auth';

type Credential = {
  credentialId?: string;
  friendlyCredentialName?: string;
  relyingPartyId?: string;
  createdAt?: Date;
};

/** Passkeys are bound to the pool's relying-party ID, which will not match a localhost origin. */
const RP_MISMATCH_HINT =
  'WebAuthn requires the origin to match the pool\'s relying-party ID. On localhost this will fail ' +
  'unless passkeyRelyingPartyId is changed to "localhost" or the app is served from that domain.';

export default function Passkeys() {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const res = await listWebAuthnCredentials();
      setCreds(res.credentials ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function register() {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await associateWebAuthnCredential();
      setNotice('Passkey registered.');
      await refresh();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`${msg} — ${RP_MISMATCH_HINT}`);
    } finally {
      setBusy(false);
    }
  }

  async function remove(credentialId?: string) {
    if (!credentialId) return;
    setError(null);
    setNotice(null);
    try {
      await deleteWebAuthnCredential({ credentialId });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <section className="token">
      <div className="token-head">
        <h3>Passkeys</h3>
        <button type="button" onClick={register} disabled={busy}>
          {busy ? 'Registering…' : 'Register a passkey'}
        </button>
      </div>

      {creds.length === 0 ? (
        <p className="muted">None registered.</p>
      ) : (
        <table className="claims">
          <tbody>
            {creds.map((c) => (
              <tr key={c.credentialId}>
                <th>{c.friendlyCredentialName || c.credentialId?.slice(0, 16) || 'passkey'}</th>
                <td>
                  <span className="muted">{c.relyingPartyId}</span>
                  {c.createdAt && <span className="muted"> · {new Date(c.createdAt).toLocaleString()}</span>}
                </td>
                <td style={{ width: '4rem' }}>
                  <button type="button" className="linkish" onClick={() => remove(c.credentialId)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
    </section>
  );
}
