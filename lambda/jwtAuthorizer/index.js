'use strict';
const AWS = require('aws-sdk');
const sm = new AWS.SecretsManager({ apiVersion: '2017-10-17' });
const crypto = require('crypto');

const SECRET_NAME = process.env.SECRET_NAME || 'reviewpilot/JwtSigningSecret';

function b64urlDecode(input){
  input = String(input || '').replace(/-/g,'+').replace(/_/g,'/');
  const pad = input.length % 4 === 2 ? '==' : (input.length % 4 === 3 ? '=' : '');
  return Buffer.from(input + pad, 'base64').toString('utf8');
}
function parseJwt(token){
  const parts = String(token||'').split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    const signature = parts[2];
    return { header, payload, signature, signingInput: parts[0] + '.' + parts[1] };
  } catch(_) { return null; }
}
function constTimeEqual(a,b){
  const ab = Buffer.from(String(a||''));
  const bb = Buffer.from(String(b||''));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function signHS256(signingInput, secret){
  return crypto.createHmac('sha256', Buffer.from(secret)).update(signingInput).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}

function simpleAuthResponse(allow, context){
  return { isAuthorized: !!allow, context: context || {} };
}

exports.handler = async (event) => {
  try {
    // Expect HTTP API REQUEST authorizer (simple responses enabled)
    const headers = (event && event.headers) || {};
    const cookieHeader = headers.Cookie || headers.cookie || '';
    const cookies = String(cookieHeader).split(/;\s*/).filter(Boolean);
    const sessionPair = cookies.find(c => c.startsWith('session='));
    if (!sessionPair) return simpleAuthResponse(false);
    const token = sessionPair.slice('session='.length);

    const parsed = parseJwt(token);
    if (!parsed || parsed.header.alg !== 'HS256') return simpleAuthResponse(false);

    const sec = await sm.getSecretValue({ SecretId: SECRET_NAME }).promise();
    const secret = sec.SecretString || (sec.SecretBinary ? Buffer.from(sec.SecretBinary, 'base64').toString('utf8') : '');
    if (!secret) return simpleAuthResponse(false);

    const expectedSig = signHS256(parsed.signingInput, secret);
    if (!constTimeEqual(parsed.signature, expectedSig)) return simpleAuthResponse(false);

    const now = Math.floor(Date.now()/1000);
    if (parsed.payload && typeof parsed.payload.exp === 'number' && parsed.payload.exp < now) return simpleAuthResponse(false);

    const userId = parsed.payload && parsed.payload.sub ? String(parsed.payload.sub) : '';
    if (!userId) return simpleAuthResponse(false);

    return simpleAuthResponse(true, { userId });
  } catch (e) {
    console.error('jwtAuthorizer error', e && (e.stack || e.message || e));
    return simpleAuthResponse(false);
  }
};
