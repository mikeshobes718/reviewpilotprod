'use strict';

const { DynamoDBClient, QueryCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');
let argon2 = null;
try { argon2 = require('argon2'); } catch (_) { /* optional */ }
const crypto = require('crypto');

const ddb = new DynamoDBClient({});
const USERS_TABLE = process.env.USERS_TABLE || 'Users';
const EMAIL_INDEX = process.env.EMAIL_INDEX || 'EmailIndex';
const TOKENS_TABLE = process.env.TOKENS_TABLE || 'Tokens';
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || '';
const POSTMARK_FROM_EMAIL = process.env.POSTMARK_FROM_EMAIL || 'support@reviewsandmarketing.com';
const APP_BASE_URL = process.env.APP_BASE_URL || 'https://reviewsandmarketing.com';

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST,OPTIONS' },
    body: JSON.stringify(body)
  };
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

async function hashPassword(password) {
  const pwd = String(password || '');
  if (!pwd) throw new Error('EMPTY_PASSWORD');
  if (argon2 && argon2.hash) {
    return await argon2.hash(pwd, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
  }
  const salt = crypto.randomBytes(16);
  const key = await new Promise((resolve, reject) => {
    crypto.scrypt(pwd, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derivedKey) => {
      if (err) reject(err); else resolve(derivedKey);
    });
  });
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === 'OPTIONS') return json(200, { ok: true });
    let body = {};
    try { body = typeof event.body === 'string' ? JSON.parse(event.body) : (event.body || {}); } catch (_) { return json(400, { error: 'INVALID_JSON' }); }
    const businessName = String(body.businessName || '').trim();
    const emailNormalized = normalizeEmail(body.email);
    const password = body.password || '';

    if (!businessName || !emailNormalized || !password) return json(400, { error: 'MISSING_FIELDS' });

    // Check existing by EmailIndex (GSI)
    const existing = await ddb.send(new QueryCommand({
      TableName: USERS_TABLE,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: 'EmailNormalized = :e',
      ExpressionAttributeValues: { ':e': { S: emailNormalized } },
      Limit: 1
    }));
    if (existing && existing.Count > 0) return json(409, { error: 'User already exists.' });

    const passwordHash = await hashPassword(password);
    const userId = (crypto.randomUUID && crypto.randomUUID()) || crypto.randomBytes(16).toString('hex');
    const nowIso = new Date().toISOString();

    await ddb.send(new PutItemCommand({
      TableName: USERS_TABLE,
      Item: {
        UserId: { S: userId },
        EmailNormalized: { S: emailNormalized },
        PasswordHash: { S: passwordHash },
        BusinessName: { S: businessName },
        IsVerified: { BOOL: false },
        CreatedAt: { S: nowIso }
      },
      ConditionExpression: 'attribute_not_exists(UserId)'
    }));

    // Create email verification token (48h TTL)
    const verifyPlain = crypto.randomBytes(32).toString('hex');
    const verifyHash = crypto.createHash('sha256').update(Buffer.from(verifyPlain,'utf8')).digest('hex');
    const ttl = Math.floor(Date.now()/1000) + 172800; // 48h
    await ddb.send(new PutItemCommand({
      TableName: TOKENS_TABLE,
      Item: {
        TokenHash: { S: verifyHash },
        UserId: { S: userId },
        TokenType: { S: 'EmailVerify' },
        ExpiresAt: { N: String(ttl) }
      }
    }));
    // Send verification email via Postmark (best-effort)
    if (POSTMARK_SERVER_TOKEN) {
      try {
        const verifyUrl = `${APP_BASE_URL}/verify?token=${encodeURIComponent(verifyPlain)}&email=${encodeURIComponent(emailNormalized)}`;
        const data = JSON.stringify({
          From: POSTMARK_FROM_EMAIL,
          To: emailNormalized,
          Subject: 'Verify your email',
          TextBody: `Welcome! Please verify your email by visiting: ${verifyUrl}`
        });
        await new Promise((resolve, reject) => {
          const https = require('https');
          const req = https.request({ hostname: 'api.postmarkapp.com', path: '/email', method: 'POST', headers: { 'X-Postmark-Server-Token': POSTMARK_SERVER_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => { res.on('data',()=>{}); res.on('end', resolve); });
          req.on('error', reject); req.write(data); req.end();
        });
      } catch (_) { /* ignore send errors */ }
    }

    return json(201, { ok: true, userId });
  } catch (e) {
    console.error('registerUser error', e && (e.stack || e.message || e));
    return json(500, { error: 'SERVER_ERROR' });
  }
};
