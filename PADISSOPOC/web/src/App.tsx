import { useEffect, useState } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { getCurrentUser } from 'aws-amplify/auth';
import SignUp from './pages/SignUp';
import ConfirmEmail from './pages/ConfirmEmail';
import Login from './pages/Login';
import PasswordlessLogin from './pages/PasswordlessLogin';
import MagicLink from './pages/MagicLink';
import MagicLinkLanding from './pages/MagicLinkLanding';
import Dashboard from './pages/Dashboard';

type AuthState = 'checking' | 'signedIn' | 'signedOut';

function useAuthState(): [AuthState, (s: AuthState) => void] {
  const [state, setState] = useState<AuthState>('checking');
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;
    getCurrentUser()
      .then(() => !cancelled && setState('signedIn'))
      .catch(() => !cancelled && setState('signedOut'));
    return () => {
      cancelled = true;
    };
    // Re-check on navigation so sign-in/sign-out is reflected immediately.
  }, [location.pathname]);

  return [state, setState];
}

export default function App() {
  const [authState] = useAuthState();

  if (authState === 'checking') {
    return <div className="shell"><p className="muted">Loading…</p></div>;
  }

  const signedIn = authState === 'signedIn';

  return (
    <div className="shell">
      <header>
        <h1>PADI SSO - Demo</h1>
      </header>

      <Routes>
        <Route path="/signup" element={signedIn ? <Navigate to="/" replace /> : <SignUp />} />
        <Route path="/confirm" element={signedIn ? <Navigate to="/" replace /> : <ConfirmEmail />} />
        <Route path="/login" element={signedIn ? <Navigate to="/" replace /> : <Login />} />
        <Route
          path="/passwordless"
          element={signedIn ? <Navigate to="/" replace /> : <PasswordlessLogin />}
        />
        {/* Both reachable signed in or out: they return tokens from the endpoint
            rather than establishing an Amplify session. */}
        <Route path="/magic-link" element={<MagicLink />} />
        {/* Where the emailed link lands — magicLinkBaseUrl points here. */}
        <Route path="/verify" element={<MagicLinkLanding />} />
        <Route path="/" element={signedIn ? <Dashboard /> : <Navigate to="/login" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}
