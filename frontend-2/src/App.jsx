import { useEffect, useState, useRef } from 'react';
import { login, exchangeCode, refreshTokenCall, IAM_URL } from './auth';

function LoginPage({ onLogin, tenantName }) {
  return (
    <div style={{ padding: '4rem 2rem', fontFamily: 'sans-serif', textAlign: 'center' }}>
      <h1 style={{ fontSize: '3.5rem', marginBottom: '1rem' }}>{tenantName}</h1>
      <p style={{ fontSize: '1.2rem', marginBottom: '2rem', color: '#555' }}>
        Welcome to the educational OAuth 2.0 Lab.
      </p>
      <button 
        onClick={onLogin}
        style={{ fontSize: '1.2rem', padding: '0.8rem 2rem', cursor: 'pointer', background: '#0056b3', color: 'white', border: 'none', borderRadius: '4px' }}
      >
        Login with Central IAM
      </button>
    </div>
  );
}

function HomePage({ 
  tenantName, authStatus, error, accessToken, idToken, refreshToken, userInfo, 
  handleUserInfo, handleRefresh, handleLogout, handleClearLocalSession 
}) {
  const decodeJwt = (token) => {
    try {
      return JSON.parse(atob(token.split('.')[1]));
    } catch {
      return null;
    }
  };

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <h1 style={{ fontSize: '3rem', borderBottom: '2px solid #ccc', paddingBottom: '1rem' }}>
        {tenantName} - Home Dashboard
      </h1>
      
      <p>Authentication status: <strong style={{ color: 'green' }}>{authStatus}</strong></p>
      
      {error && <p style={{ color: 'red', background: '#fee', padding: '1rem', border: '1px solid #fcc' }}>Error: {error}</p>}
      
      <div style={{ marginBottom: '2rem', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <button onClick={handleUserInfo} disabled={!accessToken} style={{ padding: '0.5rem 1rem' }}>Call UserInfo</button>
        <button onClick={handleRefresh} disabled={!refreshToken} style={{ padding: '0.5rem 1rem' }}>Refresh Token</button>
        <button onClick={handleLogout} style={{ padding: '0.5rem 1rem', background: '#d9534f', color: 'white', border: 'none' }}>Logout from Central IAM</button>
        <button onClick={handleClearLocalSession} style={{ padding: '0.5rem 1rem', background: '#f0ad4e', color: 'white', border: 'none' }}>Clear Local Session</button>
      </div>

      {userInfo && (
        <div style={{ background: '#f9f9f9', padding: '1.5rem', marginBottom: '1rem', border: '1px solid #eee' }}>
          <h3>User Profile (from /userinfo)</h3>
          <pre style={{ overflowX: 'auto' }}>{JSON.stringify(userInfo, null, 2)}</pre>
        </div>
      )}

      {accessToken && (
        <div style={{ background: '#f9f9f9', padding: '1.5rem', marginBottom: '1rem', border: '1px solid #eee' }}>
          <h3>Access Token</h3>
          <p><strong>Raw JWT:</strong> <span style={{ wordBreak: 'break-all', fontSize: '0.8rem', color: '#666' }}>{accessToken}</span></p>
          <h4>Decoded Claims:</h4>
          <pre style={{ overflowX: 'auto' }}>{JSON.stringify(decodeJwt(accessToken), null, 2)}</pre>
        </div>
      )}

      {idToken && (
        <div style={{ background: '#f9f9f9', padding: '1.5rem', marginBottom: '1rem', border: '1px solid #eee' }}>
          <h3>ID Token</h3>
          <p><strong>Raw JWT:</strong> <span style={{ wordBreak: 'break-all', fontSize: '0.8rem', color: '#666' }}>{idToken}</span></p>
          <h4>Decoded Claims:</h4>
          <pre style={{ overflowX: 'auto' }}>{JSON.stringify(decodeJwt(idToken), null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

function App() {
  const [authStatus, setAuthStatus] = useState('Checking...');
  const [accessToken, setAccessToken] = useState(null);
  const [idToken, setIdToken] = useState(null);
  const [refreshToken, setRefreshToken] = useState(null);
  const [userInfo, setUserInfo] = useState(null);
  const [error, setError] = useState(null);
  const processedUrl = useRef(false);

  useEffect(() => {
    const url = new URL(window.location.href);
    
    if (url.pathname === '/callback' && !processedUrl.current) {
      processedUrl.current = true;
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const err = url.searchParams.get('error');
      const errDesc = url.searchParams.get('error_description');
      
      window.history.replaceState({}, document.title, '/');

      if (err) {
        if (err === 'login_required') {
          setAuthStatus('Not Authenticated');
        } else if (err === 'access_denied') {
          setAuthStatus('Error');
          setError(`Session limit reached: ${errDesc || 'Please log out of other sessions first.'}`);
        } else {
          setAuthStatus('Error');
          setError(`${err}: ${errDesc}`);
        }
        return;
      }

      if (code && state) {
        const savedState = sessionStorage.getItem('oauth_state');
        if (state !== savedState) {
          setAuthStatus('Error');
          setError('Invalid state parameter');
          return;
        }

        setAuthStatus('Exchanging code...');
        exchangeCode(code).then(tokens => {
          setAccessToken(tokens.access_token);
          setIdToken(tokens.id_token);
          setRefreshToken(tokens.refresh_token);
          setAuthStatus('Authenticated');
        }).catch(err => {
          setAuthStatus('Error');
          setError(err.message);
        });
        return;
      }
    }

    if (!accessToken && authStatus === 'Checking...' && !processedUrl.current) {
      processedUrl.current = true;
      login(true); // silent check
    } else if (!accessToken && authStatus !== 'Exchanging code...' && authStatus !== 'Error') {
      setAuthStatus('Not Authenticated');
    }
  }, [accessToken, authStatus]);

  const handleLogin = () => login();

  const handleUserInfo = async () => {
    if (!accessToken) return;
    try {
      const res = await fetch(`${IAM_URL}/userinfo`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      if (res.ok) {
        setUserInfo(await res.json());
      } else {
        setError('Failed to fetch user info');
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleRefresh = async () => {
    if (!refreshToken) return;
    try {
      const tokens = await refreshTokenCall(refreshToken);
      setAccessToken(tokens.access_token);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleClearLocalSession = () => {
    setAccessToken(null);
    setIdToken(null);
    setRefreshToken(null);
    setUserInfo(null);
    sessionStorage.clear();
    setAuthStatus('Not Authenticated');
  };

  const handleLogout = () => {
    handleClearLocalSession();
    window.location.href = `${IAM_URL}/logout?post_logout_redirect_uri=http://localhost:3002`;
  };

  const tenantName = "Tenant 2 (Frontend 2)";

  if (authStatus === 'Checking...' || authStatus === 'Exchanging code...') {
    return <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}><h2>{authStatus}</h2></div>;
  }

  if (authStatus === 'Error' && !accessToken) {
    return (
      <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
        <h2 style={{ color: 'red' }}>Authentication Error</h2>
        <p>{error}</p>
        <button onClick={() => setAuthStatus('Not Authenticated')}>Try Again</button>
      </div>
    );
  }

  if (authStatus === 'Not Authenticated') {
    return <LoginPage onLogin={handleLogin} tenantName={tenantName} />;
  }

  return (
    <HomePage 
      tenantName={tenantName}
      authStatus={authStatus}
      error={error}
      accessToken={accessToken}
      idToken={idToken}
      refreshToken={refreshToken}
      userInfo={userInfo}
      handleUserInfo={handleUserInfo}
      handleRefresh={handleRefresh}
      handleLogout={handleLogout}
      handleClearLocalSession={handleClearLocalSession}
    />
  );
}

export default App;
