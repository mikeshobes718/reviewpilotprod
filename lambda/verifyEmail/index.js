'use strict';
const { DynamoDBClient, GetItemCommand, DeleteItemCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const crypto = require('crypto');

const ddb = new DynamoDBClient({});
const TOKENS_TABLE = process.env.TOKENS_TABLE || 'Tokens';
const USERS_TABLE = process.env.USERS_TABLE || 'Users';

function json(statusCode, body){
  return { statusCode, headers:{ 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type', 'Access-Control-Allow-Methods':'POST,OPTIONS' }, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === 'OPTIONS') return json(200, { ok: true });
    let body = {};
    try { body = typeof event.body === 'string' ? JSON.parse(event.body) : (event.body || {}); } catch (_) { return json(400, { error: 'INVALID_JSON' }); }
    const tokenPlain = String(body.token||'');
    const email = String(body.email||'').trim().toLowerCase();
    if (!tokenPlain || !email) return json(400, { error: 'MISSING_FIELDS' });

    const tokenHash = crypto.createHash('sha256').update(Buffer.from(tokenPlain, 'utf8')).digest('hex');
    const tok = await ddb.send(new GetItemCommand({ TableName: TOKENS_TABLE, Key: { TokenHash: { S: tokenHash } } }));
    const item = tok && tok.Item || null;
    if (!item || !item.TokenType || item.TokenType.S !== 'EmailVerify') return json(400, { error: 'INVALID_OR_EXPIRED' });

    const userId = item.UserId.S;
    await ddb.send(new UpdateItemCommand({ TableName: USERS_TABLE, Key: { UserId: { S: userId } }, UpdateExpression: 'SET IsVerified = :v', ExpressionAttributeValues: { ':v': { BOOL: true } } }));
    await ddb.send(new DeleteItemCommand({ TableName: TOKENS_TABLE, Key: { TokenHash: { S: tokenHash } } }));
    return json(200, { ok: true });
  } catch (e) {
    console.error('verifyEmail error', e && (e.stack || e.message || e));
    return json(500, { error: 'SERVER_ERROR' });
  }
};
