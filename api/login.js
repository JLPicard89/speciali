'use strict';

const {
  sessionCookie,
  signSession,
  verifyPassword,
} = require('./_session');

function readBody(req) {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 10000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        const type = String(req.headers['content-type'] || '');
        if (type.includes('application/json')) return resolve(JSON.parse(data || '{}'));
        const params = new URLSearchParams(data);
        resolve(Object.fromEntries(params.entries()));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const body = await readBody(req);
    if (!verifyPassword(body.password || '')) {
      return res.status(401).json({ ok: false, error: 'Password errata' });
    }

    res.setHeader('Set-Cookie', sessionCookie(signSession()));
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ ok: false, error: 'Configurazione accesso non valida' });
  }
};
