#!/usr/bin/env node
const https = require('https');
const http = require('http');

const base = process.env.SMOKE_URL || process.env.APP_BASE_URL || 'http://localhost:3000';
const paths = ['/', '/login', '/signup', '/healthz'];

function request(url) {
  return new Promise((resolve) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, (res) => {
      resolve({ url, status: res.statusCode });
    });
    req.on('error', () => resolve({ url, status: 0 }));
    req.setTimeout(5000, () => { req.destroy(); resolve({ url, status: 0 }); });
  });
}

(async () => {
  const results = await Promise.all(paths.map(p => request(base.replace(/\/$/, '') + p)));
  let ok = true;
  for (const r of results) {
    const pass = r.status >= 200 && r.status < 400;
    ok = ok && pass;
    console.log(`${pass ? 'OK ' : 'ERR'} ${r.status}\t${r.url}`);
  }
  process.exit(ok ? 0 : 1);
})();


