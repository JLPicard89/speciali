'use strict';

const crypto = require('crypto');

const COOKIE_NAME = 'tnk_portal_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function safeEqualText(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function requiredConfig() {
  const passwordHash = String(process.env.TNK_PORTAL_PASSWORD_HASH || '').toLowerCase();
  const sessionSecret = String(process.env.TNK_PORTAL_SESSION_SECRET || '');

  if (!/^[a-f0-9]{64}$/.test(passwordHash)) {
    throw new Error('TNK_PORTAL_PASSWORD_HASH is missing or invalid');
  }
  if (sessionSecret.length < 32) {
    throw new Error('TNK_PORTAL_SESSION_SECRET must contain at least 32 characters');
  }
  return { passwordHash, sessionSecret };
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password), 'utf8').digest('hex');
}

function verifyPassword(password) {
  const { passwordHash } = requiredConfig();
  return safeEqualText(hashPassword(password), passwordHash);
}

function signSession() {
  const { sessionSecret } = requiredConfig();
  const payload = base64url(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS }));
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifySession(token) {
  try {
    const { sessionSecret } = requiredConfig();
    const [payload, signature, extra] = String(token || '').split('.');
    if (!payload || !signature || extra) return false;
    const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
    if (!safeEqualText(signature, expected)) return false;
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return Number.isFinite(parsed.exp) && parsed.exp > Math.floor(Date.now() / 1000);
  } catch (_) {
    return false;
  }
}

function parseCookies(req) {
  return String(req.headers.cookie || '').split(';').reduce((acc, part) => {
    const index = part.indexOf('=');
    if (index < 0) return acc;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function sessionCookie(token) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
}

function expiredCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

module.exports = {
  COOKIE_NAME,
  expiredCookie,
  parseCookies,
  requiredConfig,
  sessionCookie,
  signSession,
  verifyPassword,
  verifySession,
};
