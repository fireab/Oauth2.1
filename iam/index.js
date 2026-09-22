const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { 
  initKeys, getJwks, generateRandomString, verifyPkce, 
  createAccessToken, createIdToken 
} = require('./crypto-utils');
const { 
  users, clients, iamSessions, authorizationCodes, refreshTokens,
  checkTenantSessionLimit, createTenantSession
} = require('./store');

const app = express();

app.use(cors({
  origin: ['http://localhost:3001', 'http://localhost:3002'],
  credentials: true
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// HTML login page template
const renderLoginPage = (error = '', authReq = '') => `
<!DOCTYPE html>
<html>
<head><title>Central IAM Login</title></head>
<body style="font-family: sans-serif; padding: 2rem;">
  <h2>Login to Central IAM</h2>
  ${error ? `<p style="color: red;">${error}</p>` : ''}
  <form method="POST" action="/login">
    <input type="hidden" name="authReq" value="${authReq}" />
    <div>
      <label>Username</label><br>
      <input type="text" name="username" value="demo" />
    </div>
    <br>
    <div>
      <label>Password</label><br>
      <input type="password" name="password" value="password123" />
    </div>
    <br>
    <button type="submit">Login</button>
  </form>
</body>
</html>
`;

// Helper to issue auth code
function issueAuthCode(res, userId, authReqData) {
  const code = generateRandomString(32);
  authorizationCodes.set(code, {
    userId,
    clientId: authReqData.client_id,
    redirectUri: authReqData.redirect_uri,
    codeChallenge: authReqData.code_challenge,
    codeChallengeMethod: authReqData.code_challenge_method,
    scope: authReqData.scope,
    expiresAt: Date.now() + 60000,
    used: false
  });
  
  console.log(`[AUTH CODE] created code=${code.substring(0, 8)}... for client=${authReqData.client_id}`);
  
  const redirectUrl = new URL(authReqData.redirect_uri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('state', authReqData.state);
  
  res.redirect(redirectUrl.toString());
}

app.get('/login', (req, res) => {
  res.send(renderLoginPage('', req.query.authReq || ''));
});

app.post('/login', (req, res) => {
  const { username, password, authReq } = req.body;
  const user = users.get(username);

  if (!user || user.password !== password) {
    return res.status(401).send(renderLoginPage('Invalid credentials', authReq));
  }

  // Create SSO Session
  const sessionId = generateRandomString(32);
  iamSessions.set(sessionId, user.id);
  
  res.cookie('iam_session', sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  });
  
  console.log(`[SSO] Created IAM session for ${user.username}`);

  if (authReq) {
    const authReqData = JSON.parse(Buffer.from(authReq, 'base64url').toString('utf-8'));
    
    // Check Tenant Session Limits
    const allowed = checkTenantSessionLimit(user.id, authReqData.client_id);
    if (!allowed) {
      const redirectUrl = new URL(authReqData.redirect_uri);
      redirectUrl.searchParams.set('error', 'access_denied');
      redirectUrl.searchParams.set('error_description', 'Tenant session limit reached');
      redirectUrl.searchParams.set('state', authReqData.state);
      return res.redirect(redirectUrl.toString());
    }
    
    createTenantSession(user.id, authReqData.client_id);
    
    // Issue Auth Code
    return issueAuthCode(res, user.id, authReqData);
  }

  res.send('Logged in directly (no auth request)');
});

app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, prompt } = req.query;

  console.log(`[AUTHORIZE] client_id=${client_id}`);

  const client = clients.get(client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('Invalid client_id or redirect_uri');
  }
  if (response_type !== 'code') return res.status(400).send('Unsupported response_type');
  if (code_challenge_method !== 'S256') return res.status(400).send('Unsupported code_challenge_method');

  const authReqData = { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method };
  const sessionId = req.cookies.iam_session;

  if (sessionId && iamSessions.has(sessionId)) {
    const userId = iamSessions.get(sessionId);
    console.log(`[SSO] existing IAM session found for user=${userId}`);
    
    // Check Tenant Session Limits
    const allowed = checkTenantSessionLimit(userId, client_id);
    if (!allowed) {
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('error', 'access_denied');
      redirectUrl.searchParams.set('error_description', 'Tenant session limit reached');
      redirectUrl.searchParams.set('state', state);
      return res.redirect(redirectUrl.toString());
    }
    
    createTenantSession(userId, client_id);
    return issueAuthCode(res, userId, authReqData);
  }

  if (prompt === 'none') {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('error', 'login_required');
    redirectUrl.searchParams.set('state', state);
    return res.redirect(redirectUrl.toString());
  }

  // Preserve request state to pass to login
  const authReq = Buffer.from(JSON.stringify(authReqData)).toString('base64url');
  res.redirect(`/login?authReq=${authReq}`);
});

app.post('/token', async (req, res) => {
  const { grant_type, client_id, redirect_uri, code, code_verifier, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
    const authCodeData = authorizationCodes.get(code);
    
    if (!authCodeData || authCodeData.used || authCodeData.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    // Single use
    authCodeData.used = true;

    if (authCodeData.clientId !== client_id || authCodeData.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    if (!verifyPkce(code_verifier, authCodeData.codeChallenge)) {
      console.log('[PKCE] verification failed');
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    console.log('[PKCE] verification successful');
    console.log('[TOKEN] authorization code received');

    const user = Array.from(users.values()).find(u => u.id === authCodeData.userId);

    const accessToken = await createAccessToken(user.id, client_id, authCodeData.scope);
    const idToken = await createIdToken(user.id, client_id, user.name, user.email);
    
    const newRefreshToken = generateRandomString(40);
    refreshTokens.set(newRefreshToken, {
      userId: user.id,
      clientId: client_id,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    console.log('[TOKEN] access token issued');

    res.json({
      access_token: accessToken,
      id_token: idToken,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: 300 // 5 min
    });
  } else if (grant_type === 'refresh_token') {
    const tokenData = refreshTokens.get(refresh_token);
    
    if (!tokenData || tokenData.expiresAt < Date.now() || tokenData.clientId !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const user = Array.from(users.values()).find(u => u.id === tokenData.userId);
    const accessToken = await createAccessToken(user.id, client_id, 'openid profile email');
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300
    });
  } else {
    res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

app.get('/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }
  
  const token = authHeader.split(' ')[1];
  const { jwtVerify } = require('jose');
  
  try {
    const { payload } = await jwtVerify(token, require('./crypto-utils').getJwks().keys[0], {
      issuer: 'http://localhost:3000',
      audience: 'demo-api'
    });
    
    const user = Array.from(users.values()).find(u => u.id === payload.sub);
    res.json({
      sub: user.id,
      name: user.name,
      email: user.email
    });
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});

app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: "http://localhost:3000",
    authorization_endpoint: "http://localhost:3000/authorize",
    token_endpoint: "http://localhost:3000/token",
    userinfo_endpoint: "http://localhost:3000/userinfo",
    jwks_uri: "http://localhost:3000/jwks.json",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["none"]
  });
});

app.get('/jwks.json', (req, res) => {
  res.json(getJwks());
});

app.get('/logout', (req, res) => {
  const { post_logout_redirect_uri } = req.query;
  const sessionId = req.cookies.iam_session;
  
  if (sessionId) {
    iamSessions.delete(sessionId);
    res.clearCookie('iam_session');
    console.log('[LOGOUT] Cleared IAM session cookie');
  }
  
  if (post_logout_redirect_uri) {
    res.redirect(post_logout_redirect_uri);
  } else {
    res.send('Logged out of IAM');
  }
});

const PORT = 3000;
initKeys().then(() => {
  app.listen(PORT, () => console.log(`IAM running on port ${PORT}`));
});
