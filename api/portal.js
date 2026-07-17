'use strict';

const fs = require('fs');
const path = require('path');
const {
  COOKIE_NAME,
  parseCookies,
  verifySession,
} = require('./_session');

function loginPage(errorMessage) {
  const error = errorMessage ? `<div class="err">${errorMessage}</div>` : '<div class="err" id="err" hidden>Password errata. Riprova.</div>';
  return `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Speciali&amp;co — Accesso</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f6f3;color:#1c1b19;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;padding:16px}.card{width:min(360px,100%);background:#fff;border:1px solid #e3e2df;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);overflow:hidden}.head{padding:28px 32px 24px;border-bottom:1px solid #e3e2df}.title{font-size:18px;font-weight:700}.sub{font-size:12px;color:#8b8a86;margin-top:3px}.body{padding:28px 32px 32px}label{display:block;font-size:12px;color:#6b6a67;margin-bottom:6px}input{width:100%;padding:11px 13px;border:1px solid #cfceca;border-radius:8px;font-size:14px;outline:none}input:focus{border-color:#1c1b19}button{width:100%;margin-top:12px;padding:11px;border:0;border-radius:8px;background:#1c1b19;color:#fff;font-size:14px;font-weight:600;cursor:pointer}.err{margin-top:12px;padding:9px 12px;border:1px solid #9b2020;border-radius:8px;background:#fdeaea;color:#9b2020;font-size:12px}.foot{padding:14px 32px;border-top:1px solid #e3e2df;text-align:center;color:#a8a7a4;font-size:11px}</style></head><body><main class="card"><div class="head"><div class="title">Speciali&amp;co</div><div class="sub">Area riservata</div></div><form class="body" id="login"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" autofocus required><button id="submit" type="submit">Accedi</button>${error}</form><div class="foot">TNK Group — Portale interno</div></main><script>document.getElementById('login').addEventListener('submit',async function(e){e.preventDefault();const b=document.getElementById('submit'),er=document.getElementById('err');b.disabled=true;b.textContent='Accesso…';if(er)er.hidden=true;try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});if(!r.ok)throw new Error();location.replace('/');}catch(_){if(er)er.hidden=false;document.getElementById('password').value='';document.getElementById('password').focus();}finally{b.disabled=false;b.textContent='Accedi';}});</script></body></html>`;
}

function removeClientGate(html) {
  return html.replace(/<div id="auth-gate"[\s\S]*?<\/div>\s*<script>\s*\(function\(\)\{[\s\S]*?async function authCheck\(\)[\s\S]*?<\/script>/, '');
}

module.exports = function handler(req, res) {
  const cookies = parseCookies(req);
  if (!verifySession(cookies[COOKIE_NAME])) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(401).send(loginPage());
  }

  try {
    const file = path.join(process.cwd(), 'index.html');
    const html = removeClientGate(fs.readFileSync(file, 'utf8'));
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(html);
  } catch (error) {
    console.error('Portal error:', error);
    return res.status(500).send(loginPage('Portale temporaneamente non disponibile.'));
  }
};
