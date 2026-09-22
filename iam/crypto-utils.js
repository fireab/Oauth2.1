const crypto = require('crypto');
const { SignJWT, generateKeyPair, exportJWK } = require('jose');

let privateKey;
let publicKey;
let jwk;

async function initKeys() {
  const { publicKey: pub, privateKey: priv } = await generateKeyPair('RS256', { extractable: true });
  privateKey = priv;
  publicKey = pub;
  
  jwk = await exportJWK(publicKey);
  jwk.kid = 'demo-key-1';
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  
  console.log('RSA Keys initialized');
}

function getJwks() {
  return {
    keys: [jwk]
  };
}

function generateRandomString(length) {
  return crypto.randomBytes(length).toString('base64url');
}

function verifyPkce(codeVerifier, codeChallenge) {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return hash === codeChallenge;
}

async function createAccessToken(userId, clientId, scope) {
  return new SignJWT({
    sub: userId,
    aud: 'demo-api',
    scope: scope
  })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuedAt()
    .setIssuer('http://localhost:3000')
    .setExpirationTime('5m')
    .sign(privateKey);
}

async function createIdToken(userId, clientId, name, email) {
  return new SignJWT({
    sub: userId,
    aud: clientId,
    name: name,
    email: email
  })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuedAt()
    .setIssuer('http://localhost:3000')
    .setExpirationTime('1h')
    .sign(privateKey);
}

module.exports = {
  initKeys,
  getJwks,
  generateRandomString,
  verifyPkce,
  createAccessToken,
  createIdToken
};
