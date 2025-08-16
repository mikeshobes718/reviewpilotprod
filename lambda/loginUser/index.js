'use strict';
const { DynamoDBClient, QueryCommand } = require('@aws-sdk/client-dynamodb');
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
let argon2 = null;
try { argon2 = require('argon2'); } catch (_) {}
const crypto = require('crypto');

const ddb = new DynamoDBClient({});
const sm = new SecretsManagerClient({});
const USERS_TABLE = process.env.USERS_TABLE || 'Users';
const EMAIL_INDEX = process.env.EMAIL_INDEX || 'EmailIndex';
const SECRET_NAME = process.env.SECRET_NAME || 'reviewpilot/JwtSigningSecret';

function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function b64urlJson(obj){ return b64url(JSON.stringify(obj)); }
function signJwtHS256(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encHeader = b64urlJson(header);
  const encPayload = b64urlJson(payload);
  const data = `${encHeader}.${encPayload}`;
  const sig = crypto.createHmac('sha256', Buffer.from(secret)).update(data).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return `${data}.${sig}`;
}
function json(statusCode, body, cookies){
  const res = {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST,OPTIONS' },
    body: JSON.stringify(body)
  };
  if (cookies && cookies.length) res.cookies = cookies;
  return res;
}
function normalizeEmail(email){ return String(email||'').trim().toLowerCase(); }
async function verifyPassword(storedHash, password){
  const pwd = String(password || '');
  if (!pwd || !storedHash) return false;
  if (storedHash.startsWith('scrypt$')){
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const saltHex = parts[1];
    const keyHex = parts[2];
    const salt = Buffer.from(saltHex, 'hex');
    const derived = await new Promise((resolve, reject) => {
      crypto.scrypt(pwd, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64*1024*1024 }, (err, dk) => {
        if (err) reject(err); else resolve(dk);
      });
    });
    const target = Buffer.from(keyHex, 'hex');
    return crypto.timingSafeEqual(derived, target);
  }
  if (storedHash.startsWith('$argon2') && argon2 && argon2.verify){
    try { return await argon2.verify(storedHash, pwd); } catch(_) { return false; }
  }
  await new Promise((resolve) => setTimeout(resolve, 40));
  return false;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === 'OPTIONS') return json(200, { ok: true });
    let body = {};
    try { body = typeof event.body === 'string' ? JSON.parse(event.body) : (event.body || {}); } catch (_) { return json(400, { error: 'INVALID_JSON' }); }
    const emailNorm = normalizeEmail(body.email);
    const password = body.password || '';
    if (!emailNorm || !password) return json(400, { error: 'MISSING_FIELDS' });

    const q = await ddb.send(new QueryCommand({
      TableName: USERS_TABLE,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: 'EmailNormalized = :e',
      ExpressionAttributeValues: { ':e': { S: emailNorm } },
      Limit: 1
    }));
    const user = (q && q.Items && q.Items[0]) ? {
      UserId: q.Items[0].UserId.S,
      PasswordHash: q.Items[0].PasswordHash.S,
      IsVerified: q.Items[0].IsVerified && (q.Items[0].IsVerified.BOOL === true)
    } : null;

    if (!user){
      await verifyPassword('scrypt$'+crypto.randomBytes(16).toString('hex')+'$'+crypto.randomBytes(64).toString('hex'), password);
      return json(401, { error: 'UNAUTHORIZED' });
    }

    const ok = await verifyPassword(user.PasswordHash, password);
    if (!ok) return json(401, { error: 'UNAUTHORIZED' });

    if (user.IsVerified !== true) return json(403, { error: 'EMAIL_NOT_VERIFIED' });

    const sec = await sm.send(new GetSecretValueCommand({ SecretId: SECRET_NAME }));
    const secret = sec.SecretString || (sec.SecretBinary ? Buffer.from(sec.SecretBinary, 'base64').toString('utf8') : '');
    if (!secret) return json(500, { error: 'MISSING_JWT_SECRET' });

    const now = Math.floor(Date.now()/1000);
    const exp = now + 60*60*8;
    const token = signJwtHS256({ sub: user.UserId, iat: now, exp }, secret);
    const cookie = `session=${token}; Max-Age=${60*60*8}; Path=/; HttpOnly; Secure; SameSite=Lax`;

    return json(200, { ok: true, userId: user.UserId }, [cookie]);
  } catch (e) {
    console.error('loginUser error', e && (e.stack || e.message || e));
    return json(500, { error: 'SERVER_ERROR' });
  }
};
