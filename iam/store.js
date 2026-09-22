const users = new Map();
users.set('demo', {
  id: 'user-1',
  username: 'demo',
  password: 'password123',
  name: 'Demo User',
  email: 'demo@example.com'
});

const clients = new Map();
clients.set('frontend-1', {
  clientId: 'frontend-1',
  redirectUris: ['http://localhost:3001/callback']
});
clients.set('frontend-2', {
  clientId: 'frontend-2',
  redirectUris: ['http://localhost:3002/callback']
});

const iamSessions = new Map();

const tenantConfig = {
  'frontend-1': {
    maxSessions: 1,
    policy: 'REJECT_NEW'
  },
  'frontend-2': {
    maxSessions: 2,
    policy: 'REVOKE_OLDEST'
  }
};

const tenantSessions = new Map();

const authorizationCodes = new Map();
const refreshTokens = new Map();

function checkTenantSessionLimit(userId, tenantId) {
  const config = tenantConfig[tenantId];
  if (!config) return true; // unlimited if no config
  
  const userTenantSessions = Array.from(tenantSessions.entries())
    .filter(([sessionId, session]) => session.userId === userId && session.tenantId === tenantId)
    .sort((a, b) => a[1].createdAt - b[1].createdAt);

  if (userTenantSessions.length >= config.maxSessions) {
    if (config.policy === 'REJECT_NEW') {
      return false; // Cannot create new
    } else if (config.policy === 'REVOKE_OLDEST') {
      const oldestSessionId = userTenantSessions[0][0];
      tenantSessions.delete(oldestSessionId);
      console.log(`[TENANT] Revoked oldest session for ${tenantId}`);
      return true;
    }
  }
  return true;
}

function createTenantSession(userId, tenantId) {
  const sessionId = Math.random().toString(36).substring(2);
  tenantSessions.set(sessionId, {
    userId,
    tenantId,
    createdAt: Date.now()
  });
  console.log(`[TENANT] Created session for ${tenantId}`);
}

module.exports = {
  users,
  clients,
  iamSessions,
  tenantSessions,
  tenantConfig,
  authorizationCodes,
  refreshTokens,
  checkTenantSessionLimit,
  createTenantSession
};
