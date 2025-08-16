'use strict';
const { DynamoDBClient, GetItemCommand, DeleteItemCommand, UpdateItemCommand, QueryCommand } = require('@aws-sdk/client-dynamodb');
let argon2 = null;
try { argon2 = require('argon2'); } catch (_) {}
const crypto = require('crypto');

const ddb = new DynamoDBClient({});
const USERS_TABLE = process.env.USERS_TABLE || 'Users';
const TOKENS_TABLE = process.env.TOKENS_TABLE || 'Tokens';
const EMAIL_INDEX = process.env.EMAIL_INDEX || 'EmailIndex';

function json(statusCode, body){
  return { statusCode, headers:{ 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type', 'Access-Control-Allow-Methods':'POST,OPTIONS' }, body: JSON.stringify(body) };
}
function normalizeEmail(email){ return String(email||'').trim().toLowerCase(); }
function sha256Hex(buf){ return crypto.createHash('sha256').update(buf).digest('hex'); }

async function hashPassword(password){
  if (argon2 && argon2.hash) return await argon2.hash(String(password||''), { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
  const salt = crypto.randomBytes(16);
  const key = await new Promise((resolve, reject) => {
    crypto.scrypt(String(password||''), salt, 64, { N:16384, r:8, p:1, maxmem:64*1024*1024 }, (err, dk)=>{ if (err) reject(err); else resolve(dk); });
  });
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === 'OPTIONS') return json(200, { ok: true });
    let body = {};
    try { body = typeof event.body === 'string' ? JSON.parse(event.body) : (event.body || {}); } catch (_) { return json(400, { error: 'INVALID_JSON' }); }
    const tokenPlain = String(body.token||'');
    const newPassword = body.newPassword || '';
    const email = normalizeEmail(body.email||'');
    if (!tokenPlain || !newPassword) return json(400, { error: 'MISSING_FIELDS' });

    const tokenHash = sha256Hex(Buffer.from(tokenPlain, 'utf8'));
    const tok = await ddb.send(new GetItemCommand({ TableName: TOKENS_TABLE, Key: { TokenHash: { S: tokenHash } } }));
    const t = tok && tok.Item || null;
    if (!t || !t.TokenType || t.TokenType.S !== 'PasswordReset') return json(400, { error: 'INVALID_OR_EXPIRED_TOKEN' });

    // If email provided, validate matches; else trust token's userId
    let userId = t.UserId.S;
    if (email) {
      const q = await ddb.send(new QueryCommand({ TableName: USERS_TABLE, IndexName: EMAIL_INDEX, KeyConditionExpression: 'EmailNormalized = :e', ExpressionAttributeValues: { ':e': { S: email } }, Limit: 1 }));
      const u = (q && q.Items && q.Items[0]) || null;
      if (!u || u.UserId.S !== userId) return json(400, { error: 'INVALID_OR_EXPIRED_TOKEN' });
    }

    const hash = await hashPassword(newPassword);
    await ddb.send(new UpdateItemCommand({ TableName: USERS_TABLE, Key: { UserId: { S: userId } }, UpdateExpression: 'SET PasswordHash = :p, IsVerified = :v', ExpressionAttributeValues: { ':p': { S: hash }, ':v': { BOOL: true } } }));
    await ddb.send(new DeleteItemCommand({ TableName: TOKENS_TABLE, Key: { TokenHash: { S: tokenHash } } }));

    return json(200, { ok: true });
  } catch (e) {
    console.error('confirmPasswordReset error', e && (e.stack || e.message || e));
    return json(500, { error: 'SERVER_ERROR' });
  }
};
