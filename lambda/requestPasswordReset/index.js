'use strict';
const { DynamoDBClient, QueryCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');

const ddb = new DynamoDBClient({});
const USERS_TABLE = process.env.USERS_TABLE || 'Users';
const TOKENS_TABLE = process.env.TOKENS_TABLE || 'Tokens';
const EMAIL_INDEX = process.env.EMAIL_INDEX || 'EmailIndex';

const https = require('https');
const APP_BASE_URL = process.env.APP_BASE_URL || 'https://reviewsandmarketing.com';

function json(statusCode, body){
  return { statusCode, headers:{ 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type', 'Access-Control-Allow-Methods':'POST,OPTIONS' }, body: JSON.stringify(body) };
}
function normalizeEmail(email){ return String(email||'').trim().toLowerCase(); }
function sha256Hex(buf){ return require('crypto').createHash('sha256').update(buf).digest('hex'); }

async function sendPostmark(to, token, email){
  const serverToken = process.env.POSTMARK_SERVER_TOKEN;
  const from = process.env.POSTMARK_FROM_EMAIL || 'support@reviewsandmarketing.com';
  if (!serverToken) return;
  const link = `${APP_BASE_URL}/reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email || to)}`;
  const data = JSON.stringify({
    From: from,
    To: to,
    Subject: 'Reset your password',
    TextBody: `Click this link to reset your password:\n\n${link}\n\nIf you didn't request this, you can ignore this email.`,
    HtmlBody: `<p>Click the button below to reset your password:</p><p><a href="${link}" style="display:inline-block;background:#10B981;color:#fff;padding:10px 14px;border-radius:6px;text-decoration:none">Reset password</a></p><p>Or copy this link into your browser:<br/><a href="${link}">${link}</a></p><p style="color:#6B7280">If you didn't request this, you can safely ignore this email.</p>`
  });
  const opts = { hostname: 'api.postmarkapp.com', path: '/email', method: 'POST', headers: { 'X-Postmark-Server-Token': serverToken, 'Content-Type':'application/json', 'Content-Length': Buffer.byteLength(data) } };
  await new Promise((resolve, reject) => { const req = https.request(opts, (res)=>{ res.on('data',()=>{}); res.on('end', resolve); }); req.on('error', reject); req.write(data); req.end(); });
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === 'OPTIONS') return json(200, { ok: true });
    let body = {};
    try { body = typeof event.body === 'string' ? JSON.parse(event.body) : (event.body || {}); } catch (_) { return json(200, { ok: true }); }
    const email = normalizeEmail(body.email);
    if (!email) return json(200, { ok: true });

    const q = await ddb.send(new QueryCommand({ TableName: USERS_TABLE, IndexName: EMAIL_INDEX, KeyConditionExpression: 'EmailNormalized = :e', ExpressionAttributeValues: { ':e': { S: email } }, Limit: 1 }));
    const item = (q && q.Items && q.Items[0]) || null;

    if (item){
      const userId = item.UserId.S;
      const plain = require('crypto').randomBytes(32).toString('hex');
      const hash = sha256Hex(Buffer.from(plain, 'utf8'));
      const now = Math.floor(Date.now()/1000);
      const ttl = now + 3600;
      await ddb.send(new PutItemCommand({ TableName: TOKENS_TABLE, Item: { TokenHash: { S: hash }, UserId: { S: userId }, TokenType: { S: 'PasswordReset' }, ExpiresAt: { N: String(ttl) } } }));
      try { await sendPostmark(item.EmailNormalized ? item.EmailNormalized.S : email, plain, email); } catch(_){ }
    }
    return json(200, { ok: true });
  } catch (e) {
    console.error('requestPasswordReset error', e && (e.stack || e.message || e));
    return json(200, { ok: true });
  }
};
