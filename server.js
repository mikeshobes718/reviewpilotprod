    // server.js (Production Ready)

    // --- 1. LOAD THE TOOLS ---
    require('dotenv').config();
    const express = require('express');
    const { initializeApp, cert } = require('firebase-admin/app');
    const { getFirestore, FieldValue } = require('firebase-admin/firestore');
    // Firebase Admin Auth is not used for end-user auth anymore
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const session = require('express-session');
    const cookieParser = require('cookie-parser');
    const helmet = require('helmet');
    const compression = require('compression');
    const rateLimit = require('express-rate-limit');
    const csurf = require('csurf');
    const morgan = require('morgan');
    const { z } = require('zod');
    const nodemailer = require('nodemailer');
    const { sendEmail } = require('./services/email');
    const crypto = require('crypto');
    const QRCode = require('qrcode');
    const PDFDocument = require('pdfkit');
    const path = require('path');
    const fs = require('fs');

    // --- 2. INITIALIZE THE APP ---
    ;(async () => {
    const app = express();
    // Parse cookies early so downstream middleware (e.g., JWT hydration) can read them
    app.use(cookieParser());
    // Behind ALB/NGINX on EB; trust proxy so secure cookies and req.secure work
    app.set('trust proxy', 1);
    const PORT = process.env.PORT || 3000;
    const HOST = '0.0.0.0'; // Necessary for some hosting platforms
        const isProduction = process.env.NODE_ENV === 'production';
        const appUrl = process.env.APP_BASE_URL
            || (process.env.HEROKU_APP_NAME ? `https://${process.env.HEROKU_APP_NAME}.herokuapp.com` : null)
            || (isProduction ? `http://localhost:${PORT}` : `http://lvh.me:${PORT}`);

    // --- 3. FIREBASE SETUP ---
        // Prefer AWS SSM Parameter Store in production; fallback to env or local file in dev
        let serviceAccount;
        try {
            const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
            const ssm = new SSMClient({ region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1' });
            const param = await ssm.send(new GetParameterCommand({ Name: '/reviewpilot/prod/google_credentials_json', WithDecryption: true }));
            serviceAccount = JSON.parse(param.Parameter.Value);
        } catch (e) {
            if (process.env.GOOGLE_CREDENTIALS) {
                serviceAccount = JSON.parse(process.env.GOOGLE_CREDENTIALS);
            } else {
                serviceAccount = require('./serviceAccountKey.json');
            }
        }
        if (serviceAccount && typeof serviceAccount.private_key === 'string') {
            serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n').replace(/\r\n/g, '\n');
        }

    initializeApp({
      credential: cert(serviceAccount),
      projectId: 'review-saas-prod',
    });
    const db = getFirestore();
        const shortDomain = process.env.SHORT_LINK_DOMAIN || 'reviewsandmarketing.com';

        // --- 3a. Cognito (end-user auth) ---
        const {
            CognitoIdentityProviderClient,
            SignUpCommand,
            ConfirmSignUpCommand,
            InitiateAuthCommand,
            GetUserCommand,
            ForgotPasswordCommand,
            ConfirmForgotPasswordCommand,
            AdminCreateUserCommand,
            AdminGetUserCommand,
            AdminSetUserPasswordCommand,
            AdminConfirmSignUpCommand,
            ListUsersCommand,
            ResendConfirmationCodeCommand,
            RespondToAuthChallengeCommand
        } = require('@aws-sdk/client-cognito-identity-provider');
        const awsRegion = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
        const cognito = new CognitoIdentityProviderClient({ region: awsRegion });
        const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'us-east-1_RG8iuFsPD';
        const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || '7jriml8d35718cdauoi149ousn';

        // --- 3b. Queue for automated sends ---
        let reviewQueue = null;
        if (process.env.REDIS_URL) {
            try {
                const { Queue, Worker } = require('bullmq');
                const IORedis = require('ioredis');
                const connectionOptions = {
                    maxRetriesPerRequest: null,
                    enableReadyCheck: false,
                    connectTimeout: 15000,
                    keepAlive: 1,
                    noDelay: true,
                    retryStrategy(times){
                        const delay = Math.min(30000, Math.pow(2, times) * 200);
                        return delay;
                    },
                    reconnectOnError(err){
                        const msg = String(err && (err.message || err));
                        if (msg.includes('READONLY') || msg.includes('ETIMEDOUT') || msg.includes('ECONNRESET')) return true;
                        return false;
                    }
                };
                // Enable TLS for ElastiCache Serverless; allow self-signed
                connectionOptions.tls = { rejectUnauthorized: false };
                const redisConnection = new IORedis(process.env.REDIS_URL, connectionOptions);
                reviewQueue = new Queue('review-requests', { connection: redisConnection });
                async function processSendJob(data){
                    const { channel, customer, merchantUid, shortLink } = data || {};
                    if (isQuietHours()) {
                        const next8am = new Date();
                        if (next8am.getHours() >= 21) next8am.setDate(next8am.getDate() + 1);
                        next8am.setHours(8,0,0,0);
                        const delay = next8am.getTime() - Date.now();
                        await reviewQueue.add('sendReviewRequest', data, { delay, attempts: 1 });
                        return;
                    }
                    await sendReviewRequest({ merchantUid, customer, channel, shortLink });
                }
                new Worker('review-requests', async (job) => { await processSendJob(job.data || {}); }, { connection: redisConnection });
            } catch (e) {
                console.error('BullMQ initialization failed; disabling queue:', e && (e.stack || e.message || e));
            }
        } else {
            console.warn('REDIS_URL not set; review-requests queue disabled');
        }

        function isQuietHours(date = new Date()) {
            // Basic quiet hours 21:00-08:00 in server time
            const hour = date.getHours();
            return (hour >= 21 || hour < 8);
        }

        // --- 3b.1 Helpers for sending and logging review requests ---
        async function isOptedOut(merchantUid, contact){
            try {
                const key = Buffer.from((contact||'').toLowerCase()).toString('base64');
                const snap = await db.collection('businesses').doc(merchantUid).collection('optouts').doc(key).get();
                return snap.exists;
            } catch(_) { return false; }
        }
        async function logEvent(merchantUid, type, payload){
            try {
                await db.collection('businesses').doc(merchantUid).collection('events').add({ type, payload: payload||{}, ts: new Date().toISOString() });
            } catch(_) {}
        }
        const UNSUBSCRIBE_SECRET = process.env.UNSUBSCRIBE_SECRET || process.env.SESSION_SECRET || 'dev-unsubscribe';
        function buildUnsubscribeUrl(uid, contactLower){
            try {
                const payload = `${uid}:${contactLower}`;
                const sig = require('crypto').createHmac('sha256', UNSUBSCRIBE_SECRET).update(payload).digest('base64url');
                const c = Buffer.from(contactLower, 'utf8').toString('base64url');
                return `${appUrl}/u?uid=${encodeURIComponent(uid)}&c=${encodeURIComponent(c)}&sig=${encodeURIComponent(sig)}`;
            } catch (_) { return null; }
        }
        async function sendReviewRequest({ merchantUid, customer, channel, shortLink }){
            try {
                const email = (customer && customer.email) ? String(customer.email).trim() : null;
                const phone = (customer && customer.phone) ? String(customer.phone).trim() : null;
                const preferred = (channel === 'sms' && phone) ? 'sms' : (email ? 'email' : null);
                if (!preferred) { await logEvent(merchantUid, 'send_skipped', { reason: 'no_contact' }); return; }
                if (email && await isOptedOut(merchantUid, email)) { await logEvent(merchantUid, 'send_skipped', { reason: 'optout_email' }); return; }
                if (phone && await isOptedOut(merchantUid, phone)) { await logEvent(merchantUid, 'send_skipped', { reason: 'optout_phone' }); return; }
                // TODO: throttling per-customer window; simple check of last 7 days
                try {
                    const sevenDaysAgo = new Date(Date.now() - 7*24*60*60*1000).toISOString();
                    const snap = await db.collection('businesses').doc(merchantUid).collection('events')
                        .where('type','==','send_email')
                        .orderBy('ts','desc').limit(20).get();
                    const sentRecently = snap.docs.some(d => {
                        const e = d.data();
                        return (e && e.payload && e.payload.email && email && e.payload.email.toLowerCase() === email.toLowerCase() && e.ts >= sevenDaysAgo);
                    });
                    if (sentRecently) { await logEvent(merchantUid, 'send_skipped', { reason: 'throttled' }); return; }
                } catch(_){ }
                // Fetch business meta for email personalization and unsubscribe
                let businessName = null;
                try {
                    const bSnap = await db.collection('businesses').doc(merchantUid).get();
                    businessName = (bSnap.exists && bSnap.data() && bSnap.data().businessName) ? bSnap.data().businessName : null;
                } catch(_) { }
                const unsubscribeUrl = email ? buildUnsubscribeUrl(merchantUid, email.toLowerCase()) : null;

                if (preferred === 'email') {
                    await sendEmail({ to: email, template: 'Review Request', data: { reviewUrl: shortLink, businessName, unsubscribeUrl } });
                    await logEvent(merchantUid, 'send_email', { email, shortLink });
                } else {
                    try {
                        const sid = process.env.TWILIO_ACCOUNT_SID;
                        const token = process.env.TWILIO_AUTH_TOKEN;
                        const from = process.env.TWILIO_FROM_SMS;
                        if (sid && token && from) {
                            const tw = require('twilio')(sid, token);
                            await tw.messages.create({ to: phone, from, body: `Thanks for your visit! Would you leave us a quick 5-star review? ${shortLink}` });
                            await logEvent(merchantUid, 'send_sms', { phone, shortLink });
                        } else if (email) {
                            await sendEmail({ to: email, template: 'Review Request', data: { reviewUrl: shortLink, businessName, unsubscribeUrl } });
                            await logEvent(merchantUid, 'send_email', { email, shortLink, fallbackFrom: 'sms' });
                        } else {
                            await logEvent(merchantUid, 'send_skipped', { reason: 'sms_unavailable' });
                        }
                    } catch (e) {
                        await logEvent(merchantUid, 'send_error', { message: 'twilio_fail', detail: String(e && e.message || e) });
                        if (email) {
                            await sendEmail({ to: email, template: 'Review Request', data: { reviewUrl: shortLink, businessName, unsubscribeUrl } });
                            await logEvent(merchantUid, 'send_email', { email, shortLink, fallbackFrom: 'sms' });
                        }
                    }
                }
            } catch (e) {
                console.error('sendReviewRequest error', e);
                await logEvent(merchantUid, 'send_error', { message: String(e && e.message || e) });
            }
        }

        // Weekly reports scheduler (optional; set ENABLE_WEEKLY_REPORT_CRON=1)
        async function runWeeklyReports(){
            try {
                const q = await db.collection('businesses').where('reportSettings.enabled','==', true).limit(50).get();
                for (const d of q.docs){
                    const b = d.data() || {};
                    if (b.subscriptionStatus !== 'active') continue;
                    const email = (b.reportSettings && b.reportSettings.email) || b.email || null;
                    if (!email) continue;
                    const sinceMs = Date.now() - 7*24*60*60*1000;
                    const fsnap = await db.collection('businesses').doc(d.id).collection('feedback').orderBy('createdAt','desc').limit(500).get();
                    const rows = fsnap.docs.map(x=>x.data()).filter(x => { try { return new Date(x.createdAt).getTime() >= sinceMs; } catch(_){ return false; } });
                    let total = rows.length, sum = 0, conversions = 0; const counts = {1:0,2:0,3:0,4:0,5:0};
                    rows.forEach(f=>{ const r = Number(f.rating)||0; if (r>=1&&r<=5){ counts[r]++; sum+=r; } if (r===5 && (f.type==='positive'||f.type==='contact')) conversions++; });
                    const avg = total ? (sum/total).toFixed(2) : '0.00';
                    await sendEmail({ to: email, template: 'Weekly Analytics Report', data: { total, avg, conversions, loginUrl: `${appUrl}/dashboard` } });
                }
            } catch (e) { console.error('weekly reports error', e); }
        }
        if (process.env.ENABLE_WEEKLY_REPORT_CRON === '1') {
            setInterval(runWeeklyReports, 24*60*60*1000);
        }

        // --- 3b.2 Google Places server-side search (keep users on dashboard)
        app.get('/api/places/search', async (req, res) => {
            try {
                const apiKey = process.env.GOOGLE_MAPS_API_KEY || process.env.GOOGLE_PLACES_API_KEY || '';
                const q = (req.query.q || '').toString().trim();
                if (!apiKey || !q) return res.json({ places: [] });
                const r = await fetch('https://places.googleapis.com/v1/places:searchText', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Goog-Api-Key': apiKey,
                        'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress'
                    },
                    body: JSON.stringify({ textQuery: q })
                });
                if (!r.ok) return res.json({ places: [] });
                const j = await r.json().catch(()=>({ places: [] }));
                const out = (j.places||[]).slice(0,8).map(p => ({ id: p.id, name: (p.displayName && p.displayName.text) || '', address: p.formattedAddress || '' }));
                res.json({ places: out });
            } catch (e) { console.error('places search error', e); res.json({ places: [] }); }
        });

        

        // --- 3c. KMS helpers for encrypting tokens ---
        const { KMSClient, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');
        const kms = new KMSClient({ region: awsRegion });
        const KMS_KEY_ID = process.env.KMS_KEY_ID || undefined; // use default if absent
        const KMS_FALLBACK_ARN = process.env.KMS_FALLBACK_ARN || null;
        async function encryptString(plain) {
            try {
                const keyId = KMS_KEY_ID;
                const cmd = new EncryptCommand({ KeyId: keyId, Plaintext: Buffer.from(plain) });
                const res = await kms.send(cmd);
                return Buffer.from(res.CiphertextBlob).toString('base64');
            } catch (e) {
                const msg = (e && (e.message || e.__type || '')) || '';
                const isAliasMissing = (e && e.__type === 'NotFoundException') || /NotFoundException/i.test(String(e && e.name)) || /alias\//i.test(msg);
                if (isAliasMissing && KMS_FALLBACK_ARN) {
                    try {
                        const cmd2 = new EncryptCommand({ KeyId: KMS_FALLBACK_ARN, Plaintext: Buffer.from(plain) });
                        const res2 = await kms.send(cmd2);
                        console.warn('KMS alias missing; used fallback ARN for encryption');
                        return Buffer.from(res2.CiphertextBlob).toString('base64');
                    } catch (e2) {
                        console.error('KMS fallback encryption failed', e2);
                        throw e2;
                    }
                }
                throw e;
            }
        }
        async function decryptString(cipherB64) {
            const cmd = new DecryptCommand({ CiphertextBlob: Buffer.from(cipherB64, 'base64') });
            const res = await kms.send(cmd);
            return Buffer.from(res.Plaintext).toString('utf8');
        }

        // --- 3d. Square OAuth ---
        const SQUARE_APP_ID = process.env.SQUARE_APP_ID || '';
        let SQUARE_APP_SECRET = process.env.SQUARE_APP_SECRET || '';
        if (!SQUARE_APP_SECRET) {
            try {
                const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
                const ssm2 = new SSMClient({ region: awsRegion });
                const p = await ssm2.send(new GetParameterCommand({ Name: '/reviewpilot/prod/square_app_secret', WithDecryption: true }));
                SQUARE_APP_SECRET = p.Parameter.Value;
            } catch (_) { /* ignore */ }
        }
        const SQUARE_REDIRECT_URL = process.env.SQUARE_REDIRECT_URL || (appUrl ? appUrl + '/api/square/callback' : '');
        const SQUARE_SCOPES = process.env.SQUARE_SCOPES || 'PAYMENTS_READ,ORDERS_READ,CUSTOMERS_READ';

        // Signed state helpers for OAuth (avoid reliance on volatile server sessions)
        const OAUTH_STATE_SECRET = process.env.OAUTH_STATE_SECRET || process.env.SESSION_SECRET || 'dev-oauth-state';
        function createSignedState(data) {
            try {
                const payload = Buffer.from(JSON.stringify(data), 'utf8').toString('base64url');
                const sig = crypto.createHmac('sha256', OAUTH_STATE_SECRET).update(payload).digest('base64url');
                return `${payload}.${sig}`;
            } catch (_) { return null; }
        }
        function verifySignedState(state) {
            try {
                const parts = String(state || '').split('.');
                if (parts.length !== 2) return null;
                const [payload, sig] = parts;
                const exp = crypto.createHmac('sha256', OAUTH_STATE_SECRET).update(payload).digest('base64url');
                if (sig !== exp) return null;
                const json = Buffer.from(payload, 'base64url').toString('utf8');
                return JSON.parse(json);
            } catch (_) { return null; }
        }
        function getUserIdFromRequest(req) {
            try {
                const raw = req.cookies && req.cookies.session;
                if (raw) {
                    const jwt = require('jsonwebtoken');
                    const d = jwt.decode(raw);
                    if (d && d.sub) return d.sub;
                }
            } catch(_) {}
            // Fallback to session if present, but do not require it
            try { if (req.session && req.session.user && req.session.user.uid) return req.session.user.uid; } catch(_) {}
            return null;
        }

        // --- Auth guards (define before routes use them) ---
        const requireLogin = (req, res, next) => {
            const uid = getUserIdFromRequest(req);
            if (uid) {
                // Optionally backfill req.session.user for downstream code that still reads it
                try { req.session.user = req.session.user || { uid, email: null, displayName: null }; } catch(_) {}
                return next();
            }
            return res.redirect(302, '/login');
        };
        const requireAccess = async (req, res, next) => {
            try {
                const uid = getUserIdFromRequest(req);
                if (!uid) return res.redirect(302, '/login');

                // Check subscription/trial access
                let status = null;
                let trialEndsAt = null;
                try {
                    const doc = await db.collection('businesses').doc(uid).get();
                    if (doc.exists) {
                        const data = doc.data() || {};
                        status = data.subscriptionStatus || null;
                        trialEndsAt = data.trialEndsAt || null;
                    }
                } catch (_) {}
                const now = new Date();
                const isActive = status === 'active';
                const isTrial = status === 'trial' && trialEndsAt && (new Date(trialEndsAt) > now);
                const hasAccess = isActive || isTrial;
                if (!hasAccess) {
                    if (!uid) return res.redirect(302, '/login');
                    return res.redirect(302, '/pricing');
                }
                return next();
            } catch (_) { return res.redirect(302, '/pricing'); }
        };

        // POS OAuth (Square) - Initiate via POST (AJAX) or GET fallback
        app.post('/auth/pos/square/connect', async (req, res) => {
            try {
                const uid = getUserIdFromRequest(req);
                try { console.log('Square connect POST: cookies=', Object.keys(req.cookies||{}), 'hasSessionCookie=', !!(req.cookies&&req.cookies.session), 'uid=', uid); } catch(_) {}
                if (!uid) return res.status(401).json({ error: 'unauthorized' });
                const state = createSignedState({ uid, nonce: crypto.randomBytes(12).toString('hex'), iat: Date.now() });
                const authUrl = `https://connect.squareup.com/oauth2/authorize?client_id=${encodeURIComponent(SQUARE_APP_ID)}&scope=${encodeURIComponent(SQUARE_SCOPES)}&session=false&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(SQUARE_REDIRECT_URL)}`;
                return res.json({ url: authUrl });
            } catch (e) {
                console.error('square connect error', e);
                return res.status(500).json({ error: 'server_error' });
            }
        });
        // GET fallback alias
        app.get('/auth/pos/square/connect', (req, res) => {
            const uid = getUserIdFromRequest(req);
            try { console.log('Square connect GET: cookies=', Object.keys(req.cookies||{}), 'hasSessionCookie=', !!(req.cookies&&req.cookies.session), 'uid=', uid); } catch(_) {}
            if (!uid) return res.redirect('/login');
            const state = createSignedState({ uid, nonce: crypto.randomBytes(12).toString('hex'), iat: Date.now() });
            const authUrl = `https://connect.squareup.com/oauth2/authorize?client_id=${encodeURIComponent(SQUARE_APP_ID)}&scope=${encodeURIComponent(SQUARE_SCOPES)}&session=false&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(SQUARE_REDIRECT_URL)}`;
            res.redirect(authUrl);
        });
        app.get('/api/square/connect', requireLogin, (req, res) => {
            const state = crypto.randomBytes(16).toString('hex');
            req.session.square_oauth_state = state;
            const authUrl = `https://connect.squareup.com/oauth2/authorize?client_id=${encodeURIComponent(SQUARE_APP_ID)}&scope=${encodeURIComponent(SQUARE_SCOPES)}&session=false&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(SQUARE_REDIRECT_URL)}`;
            res.redirect(authUrl);
        });

        app.get('/api/square/callback', async (req, res) => {
            try {
                const { code, state } = req.query || {};
                if (!code || !state) return res.status(400).send('invalid_state');
                const parsed = verifySignedState(state);
                const ownerUid = parsed && parsed.uid ? parsed.uid : getUserIdFromRequest(req);
                if (!ownerUid) return res.status(400).send('invalid_state');
                // Exchange code
                const tokenResp = await fetch('https://connect.squareup.com/oauth2/token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        client_id: SQUARE_APP_ID,
                        client_secret: SQUARE_APP_SECRET,
                        code,
                        grant_type: 'authorization_code',
                        redirect_uri: SQUARE_REDIRECT_URL
                    })
                });
                if (!tokenResp.ok) {
                    const t = await tokenResp.text();
                    console.error('square token error', t);
                    return res.status(400).send('oauth_error');
                }
                const tokenJson = await tokenResp.json();
                const encAccess = await encryptString(tokenJson.access_token);
                const encRefresh = tokenJson.refresh_token ? await encryptString(tokenJson.refresh_token) : null;
                await db.collection('businesses').doc(ownerUid).set({
                    square: {
                        merchantId: tokenJson.merchant_id || null,
                        access: encAccess,
                        refresh: encRefresh,
                        expiresAt: tokenJson.expires_at || null,
                        scope: tokenJson.scope || SQUARE_SCOPES
                    }
                }, { merge: true });
                // Mark connection metadata for UI
                await db.collection('businesses').doc(ownerUid).set({
                    posConnection: {
                        isConnected: true,
                        provider: 'square',
                        connectedAt: new Date().toISOString(),
                        scopesGranted: (tokenJson.scope || '').split(',').map(s => s.trim()).filter(Boolean)
                    }
                }, { merge: true });
                // For server flow, redirect back to dashboard with success flag
                res.redirect('/dashboard?pos=square_connected');
            } catch (e) {
                console.error('square callback error', e);
                res.status(500).send('server_error');
            }
        });
        // Callback alias (if Square dashboard uses this URL)
        app.get('/auth/pos/square/callback', async (req, res) => {
            try {
                const { code, state } = req.query || {};
                if (!code || !state) return res.status(400).send('invalid_state');
                const parsed = verifySignedState(state);
                const ownerUid = parsed && parsed.uid ? parsed.uid : getUserIdFromRequest(req);
                if (!ownerUid) return res.status(400).send('invalid_state');
                const tokenResp = await fetch('https://connect.squareup.com/oauth2/token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        client_id: SQUARE_APP_ID,
                        client_secret: SQUARE_APP_SECRET,
                        code,
                        grant_type: 'authorization_code',
                        redirect_uri: SQUARE_REDIRECT_URL
                    })
                });
                if (!tokenResp.ok) {
                    const t = await tokenResp.text();
                    console.error('square token error (alias)', t);
                    return res.status(400).send('oauth_error');
                }
                const tokenJson = await tokenResp.json();
                const encAccess = await encryptString(tokenJson.access_token);
                const encRefresh = tokenJson.refresh_token ? await encryptString(tokenJson.refresh_token) : null;
                await db.collection('businesses').doc(ownerUid).set({
                    square: {
                        merchantId: tokenJson.merchant_id || null,
                        access: encAccess,
                        refresh: encRefresh,
                        expiresAt: tokenJson.expires_at || null,
                        scope: tokenJson.scope || SQUARE_SCOPES
                    }
                }, { merge: true });
                await db.collection('businesses').doc(ownerUid).set({
                    posConnection: {
                        isConnected: true,
                        provider: 'square',
                        connectedAt: new Date().toISOString(),
                        scopesGranted: (tokenJson.scope || '').split(',').map(s => s.trim()).filter(Boolean)
                    }
                }, { merge: true });
                res.redirect('/dashboard?pos=square_connected');
            } catch (e) {
                console.error('square callback error (alias)', e);
                res.status(500).send('server_error');
            }
        });

        // Connection status for UI single source of truth
        app.get('/api/pos/connection-status', async (req, res) => {
            try {
                const uid = getUserIdFromRequest(req);
                if (!uid) return res.status(401).json({ posConnection: { isConnected: false } });
                const doc = await db.collection('businesses').doc(uid).get();
                const d = doc.exists ? (doc.data() || {}) : {};
                const squareMeta = d.square || {};
                const posMeta = d.posConnection || {};
                const payload = {
                    posConnection: {
                        isConnected: !!(squareMeta.access || posMeta.isConnected),
                        provider: squareMeta.merchantId ? 'square' : (posMeta.provider || null),
                        connectedAt: posMeta.connectedAt || null,
                        scopesGranted: (posMeta.scopesGranted && Array.isArray(posMeta.scopesGranted)) ? posMeta.scopesGranted : ((squareMeta.scope || '').split(',').map(s => s.trim()).filter(Boolean))
                    }
                };
                return res.json(payload);
            } catch (e) {
                console.error('connection-status error', e);
                return res.status(500).json({ posConnection: { isConnected: false } });
            }
        });

        // POS: repair status if tokens exist but status not set (safety net)
        app.post('/api/pos/repair-status', async (req, res) => {
            try {
                const uid = getUserIdFromRequest(req);
                if (!uid) return res.status(401).json({ ok: false, reason: 'unauthorized' });
                const ref = db.collection('businesses').doc(uid);
                const snap = await ref.get();
                if (!snap.exists) return res.json({ ok: false, reason: 'no_business' });
                const d = snap.data() || {};
                const squareMeta = d.square || {};
                if (squareMeta && squareMeta.access) {
                    await ref.set({
                        posConnection: {
                            isConnected: true,
                            provider: 'square',
                            connectedAt: new Date().toISOString(),
                            scopesGranted: (squareMeta.scope || '').split(',').map(s => s.trim()).filter(Boolean)
                        }
                    }, { merge: true });
                    return res.json({ ok: true, repaired: true });
                }
                return res.json({ ok: false, reason: 'no_tokens' });
            } catch (e) {
                console.error('repair-status error', e);
                return res.status(500).json({ ok: false, reason: 'server' });
            }
        });

        // Onboarding status (dynamic, single source of truth)
        app.get('/api/onboarding/status', async (req, res) => {
            try {
                const uid = getUserIdFromRequest(req);
                if (!uid) return res.status(401).json({ hasPlaceId:false, hasShortLink:false, posConnected:false, sentFirst:false });
                const ref = db.collection('businesses').doc(uid);
                const doc = await ref.get();
                const b = doc.exists ? (doc.data() || {}) : {};
                let posConnected = !!(b.posConnection && b.posConnection.isConnected);
                if (!posConnected && b.square && b.square.access) posConnected = true;
                let sentFirst = false;
                try {
                    const es = await ref.collection('events').orderBy('ts', 'desc').limit(25).get();
                    sentFirst = es.docs.some(d => {
                        const t = (d.data() || {}).type || '';
                        return t === 'send_email' || t === 'send_sms';
                    });
                } catch(_) {}
                return res.json({
                    hasPlaceId: !!b.googlePlaceId,
                    hasShortLink: !!(b.shortSlug || b.googlePlaceId),
                    posConnected,
                    sentFirst
                });
            } catch (e) {
                console.error('onboarding status error', e);
                return res.status(200).json({ hasPlaceId:false, hasShortLink:false, posConnected:false, sentFirst:false });
            }
        });

        // POS: disconnect Square (revoke token, clear metadata)
        app.post('/auth/pos/square/disconnect', async (req, res) => {
            try {
                const uid = getUserIdFromRequest(req);
                if (!uid) return res.status(401).json({ ok: false, reason: 'unauthorized' });
                const ref = db.collection('businesses').doc(uid);
                const snap = await ref.get();
                const d = snap.exists ? (snap.data() || {}) : {};
                const squareMeta = d.square || {};

                // Best-effort revoke at Square
                if (squareMeta && squareMeta.access) {
                    try {
                        const tokenCipher = squareMeta.access;
                        const accessToken = await decryptString(tokenCipher);
                        const revokeResp = await fetch('https://connect.squareup.com/oauth2/revoke', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Client ${SQUARE_APP_SECRET}`
                            },
                            body: JSON.stringify({ client_id: SQUARE_APP_ID, access_token: accessToken })
                        });
                        if (!revokeResp.ok) {
                            const t = await revokeResp.text().catch(() => '');
                            console.warn('square revoke failed', t);
                        }
                    } catch (e) {
                        console.warn('square revoke error', e);
                    }
                }

                await ref.set({
                    square: {
                        merchantId: null,
                        access: null,
                        refresh: null,
                        expiresAt: null,
                        scope: null
                    },
                    posConnection: {
                        isConnected: false,
                        provider: null,
                        connectedAt: null,
                        scopesGranted: []
                    }
                }, { merge: true });

                return res.json({ ok: true, disconnected: true });
            } catch (e) {
                console.error('square disconnect error', e);
                return res.status(500).json({ ok: false, reason: 'server_error' });
            }
        });

        // Save Square automation settings
        app.post('/integrations/square/settings', requireLogin, async (req, res) => {
            try {
                const { autoSend, delayMinutes, channel } = req.body || {};
                const settings = {
                    autoSend: !!autoSend,
                    delayMinutes: Math.max(0, Math.min(10080, parseInt(delayMinutes || '0', 10))),
                    channel: channel === 'sms' ? 'sms' : 'email'
                };
                await db.collection('businesses').doc(req.session.user.uid).set({ squareSettings: settings }, { merge: true });
                res.redirect('/dashboard');
            } catch (e) { console.error('save square settings', e); res.redirect('/dashboard?e=' + encodeURIComponent('Could not save settings')); }
        });

        // Simple alert notifier (Slack webhook if configured)
        async function notifyAlert(message, extra){
            try {
                const hook = process.env.SLACK_WEBHOOK_URL || '';
                if (!hook) return;
                const body = { text: `:rotating_light: ${message}${extra ? `\n\n${typeof extra === 'string' ? extra : JSON.stringify(extra)}` : ''}` };
                await fetch(hook, { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify(body) });
            } catch(_) {}
        }

        // Square webhook
        app.post('/api/webhooks/square', express.raw({ type: 'application/json' }), async (req, res) => {
            try {
                const signatureKey = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || '';
                const sigHeader = req.get('x-square-hmacsha256-signature') || req.get('x-square-signature') || '';
                const bodyStr = req.body.toString('utf8');
                if (signatureKey && sigHeader) {
                    const hmac = crypto.createHmac('sha256', signatureKey).update(bodyStr).digest('base64');
                    if (hmac !== sigHeader) { return res.status(401).send('invalid_signature'); }
                }
                const payload = JSON.parse(bodyStr);
                const type = payload?.type || payload?.event_type || '';
                if (!type) return res.status(200).send('ok');

                if (type.includes('payment') && JSON.stringify(payload).includes('COMPLETED')) {
                    const merchantId = payload?.merchant_id || payload?.data?.merchant_id || null;
                    const customerId = payload?.data?.object?.payment?.customer_id || null;
                    const businessDoc = await db.collection('businesses').doc(merchantId || req.query.m || '').get();
                    // Fallback: we store merchantId as Cognito sub; map Square merchant via doc.square.merchantId
                    let biz = businessDoc.exists ? businessDoc.data() : null;
                    if (!biz && merchantId) {
                        const snap = await db.collection('businesses').where('square.merchantId', '==', merchantId).limit(1).get();
                        if (!snap.empty) { biz = snap.docs[0].data(); }
                    }
                    if (!biz) return res.status(200).send('ok');
                    const settings = biz.squareSettings || { autoSend: false };
                    if (!settings.autoSend) return res.status(200).send('ok');
                    // Decrypt token
                    const tokenCipher = biz?.square?.access;
                    if (!tokenCipher) return res.status(200).send('ok');
                    const accessToken = await decryptString(tokenCipher);
                    // Fetch customer contact
                    let customer = {};
                    if (customerId) {
                        const cResp = await fetch(`https://connect.squareup.com/v2/customers/${customerId}`, { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } });
                        if (cResp.ok) {
                            const cj = await cResp.json();
                            const c = cj?.customer || {};
                            customer = { email: c?.email_address || null, phone: c?.phone_number || null };
                        }
                    }
                    // Short link
                    const slug = biz.shortSlug || 'MERCHANT';
                    const shortLink = `${shortDomain}/${slug}`;
                    // Compute delay
                    const delayMs = Math.max(0, (settings.delayMinutes || 0) * 60 * 1000);
                    if (reviewQueue) {
                        await reviewQueue.add('sendReviewRequest', { channel: settings.channel || 'email', customer, merchantUid: (biz.uid || biz.id || req.session.user.uid), shortLink }, { delay: delayMs, attempts: 1 });
                    } else {
                        // Fallback: run in-process with timeout (non-durable)
                        setTimeout(() => {
                            sendReviewRequest({ merchantUid: (biz.uid || biz.id || req.session.user.uid), customer, channel: settings.channel || 'email', shortLink });
                        }, delayMs);
                    }
                    // POS health: last sync timestamp
                    try { await db.collection('businesses').doc(biz.uid || req.session.user.uid).set({ posLastSyncAt: new Date().toISOString() }, { merge: true }); } catch(_) {}
                }
                res.status(200).send('ok');
            } catch (e) { console.error('square webhook error', e); notifyAlert('Square webhook error', e && (e.stack || e.message || e)); res.status(200).send('ok'); }
        });

        // Square payments backfill and daily sync
        async function fetchSquarePayments(accessToken, params){
            const query = new URLSearchParams(params).toString();
            let url = `https://connect.squareup.com/v2/payments?${query}`;
            let items = [];
            for (let i=0; i<20; i++) { // hard cap pages
                const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type':'application/json' } });
                if (!r.ok) { const t = await r.text().catch(()=>r.statusText); throw new Error(`square_payments_http_${r.status}: ${t}`); }
                const j = await r.json();
                if (Array.isArray(j.payments)) items = items.concat(j.payments);
                if (j.cursor) { url = `https://connect.squareup.com/v2/payments?cursor=${encodeURIComponent(j.cursor)}`; } else { break; }
            }
            return items;
        }

        async function processSquarePayment({ businessRef, businessData, payment, accessToken }){
            try {
                if (!payment || payment.status !== 'COMPLETED') return false;
                const paymentId = payment.id;
                const syncedRef = businessRef.collection('syncedPayments').doc(paymentId);
                const exists = await syncedRef.get();
                if (exists.exists) return false; // idempotent

                // Fetch customer contact
                let customer = {};
                const customerId = payment.customer_id;
                if (customerId) {
                    try {
                        const cResp = await fetch(`https://connect.squareup.com/v2/customers/${customerId}`, { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type':'application/json' } });
                        if (cResp.ok) {
                            const cj = await cResp.json();
                            const c = cj?.customer || {};
                            customer = { email: c.email_address || null, phone: c.phone_number || null };
                        }
                    } catch(_) { /* ignore */ }
                }

                // Short link
                const googlePlaceId = businessData.googlePlaceId || null;
                const slug = businessData.shortSlug || (googlePlaceId ? googlePlaceId : 'SETUP');
                const shortLink = `${shortDomain}/${slug}`;

                // Auto-send settings
                const settings = businessData.squareSettings || { autoSend: false, delayMinutes: 0, channel: 'email' };

                // Mark synced first to avoid double work in concurrent calls
                await syncedRef.set({ ts: new Date().toISOString(), amount: payment.amount_money?.amount || null, currency: payment.amount_money?.currency || null, customerId: customerId || null });

                // Enqueue send if enabled
                if (settings.autoSend) {
                    const delayMs = Math.max(0, (settings.delayMinutes || 0) * 60 * 1000);
                    if (reviewQueue) {
                        await reviewQueue.add('sendReviewRequest', { channel: settings.channel || 'email', customer, merchantUid: (businessData.uid || businessRef.id), shortLink }, { delay: delayMs, attempts: 1 });
                    } else {
                        setTimeout(() => { sendReviewRequest({ merchantUid: (businessData.uid || businessRef.id), customer, channel: settings.channel || 'email', shortLink }); }, delayMs);
                    }
                    try { await businessRef.collection('events').add({ type: 'enqueue_send', ts: new Date().toISOString(), payload: { paymentId, shortLink, channel: settings.channel || 'email' } }); } catch(_) {}
                }

                // Update last sync
                try { await businessRef.set({ posLastSyncAt: new Date().toISOString() }, { merge: true }); } catch(_) {}
                return true;
            } catch (e) {
                console.error('processSquarePayment error', e && (e.stack || e.message || e));
                notifyAlert('Square processPayment error', { uid: businessData && businessData.uid, err: e && (e.stack || e.message || e) });
                return false;
            }
        }

        const requireMerchantAuth = (req, res, next) => {
            if (!req.session || !req.session.user) return res.status(401).json({ error: 'unauthorized' });
            next();
        };

        // Backfill recent payments (default 30 days; up to 90)
        app.post('/integrations/square/backfill', requireMerchantAuth, async (req, res) => {
            try {
                const uid = req.session.user.uid;
                const businessRef = db.collection('businesses').doc(uid);
                const snap = await businessRef.get();
                if (!snap.exists) return res.status(404).json({ error: 'merchant_not_found' });
                const biz = { uid, ...(snap.data() || {}) };
                const tokenCipher = biz?.square?.access;
                if (!tokenCipher) return res.status(400).json({ error: 'not_connected' });
                const accessToken = await decryptString(tokenCipher);
                const days = Math.max(1, Math.min(90, parseInt((req.body && req.body.days) || (req.query && req.query.days) || '30', 10)));
                const end = new Date();
                const begin = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
                const params = { begin_time: begin.toISOString(), end_time: end.toISOString(), sort_order: 'ASC' };

                let processed = 0;
                const payments = await fetchSquarePayments(accessToken, params);
                for (const p of payments) {
                    const ok = await processSquarePayment({ businessRef, businessData: biz, payment: p, accessToken });
                    if (ok) processed++;
                }
                return res.json({ ok: true, scanned: payments.length, processed });
            } catch (e) {
                console.error('square backfill error', e && (e.stack || e.message || e));
                return res.status(500).json({ error: 'server_error' });
            }
        });

        // Daily incremental sync (last 24h)
        app.post('/integrations/square/sync-daily', requireMerchantAuth, async (req, res) => {
            try {
                const uid = req.session.user.uid;
                const businessRef = db.collection('businesses').doc(uid);
                const snap = await businessRef.get();
                if (!snap.exists) return res.status(404).json({ error: 'merchant_not_found' });
                const biz = { uid, ...(snap.data() || {}) };
                const tokenCipher = biz?.square?.access;
                if (!tokenCipher) return res.status(400).json({ error: 'not_connected' });
                const accessToken = await decryptString(tokenCipher);
                const end = new Date();
                const begin = new Date(Date.now() - 24 * 60 * 60 * 1000);
                const params = { begin_time: begin.toISOString(), end_time: end.toISOString(), sort_order: 'ASC' };

                let processed = 0;
                const payments = await fetchSquarePayments(accessToken, params);
                for (const p of payments) {
                    const ok = await processSquarePayment({ businessRef, businessData: biz, payment: p, accessToken });
                    if (ok) processed++;
                }
                return res.json({ ok: true, scanned: payments.length, processed });
            } catch (e) {
                console.error('square daily sync error', e && (e.stack || e.message || e));
                return res.status(500).json({ error: 'server_error' });
            }
        });

        // Leaderless daily sync for all merchants (loopback-only)
        app.post('/tasks/square/sync-all-daily', async (req, res) => {
            try {
                const remote = (req.ip || '').toString();
                if (!(remote.includes('127.0.0.1') || remote.includes('::1'))) {
                    return res.status(403).json({ error: 'forbidden' });
                }
                const end = new Date();
                const begin = new Date(Date.now() - 24 * 60 * 60 * 1000);
                const paramsBase = { begin_time: begin.toISOString(), end_time: end.toISOString(), sort_order: 'ASC' };
                let scannedTotal = 0, processedTotal = 0, merchants = 0;

                const snap = await db.collection('businesses').limit(500).get();
                for (const d of snap.docs) {
                    const biz = { uid: d.id, ...(d.data() || {}) };
                    const tokenCipher = biz?.square?.access;
                    if (!tokenCipher) continue;
                    merchants++;
                    try {
                        const accessToken = await decryptString(tokenCipher);
                        const payments = await fetchSquarePayments(accessToken, paramsBase);
                        scannedTotal += payments.length;
                        for (const p of payments) {
                            const ok = await processSquarePayment({ businessRef: db.collection('businesses').doc(biz.uid), businessData: biz, payment: p, accessToken });
                            if (ok) processedTotal++;
                        }
                    } catch (e) {
                        console.warn('sync-all merchant error', biz.uid, e && (e.message || e));
                    }
                }
                return res.json({ ok: true, merchants, scanned: scannedTotal, processed: processedTotal });
            } catch (e) {
                console.error('sync-all-daily error', e && (e.stack || e.message || e));
                return res.status(500).json({ error: 'server_error' });
            }
        });

        // --- Square historical backfill and incremental sync ---
        async function fetchSquarePaymentsPaged(accessToken, beginIso, endIso) {
            const payments = [];
            let cursor = null;
            const base = 'https://connect.squareup.com/v2/payments';
            const headers = { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' };
            let guard = 0;
            do {
                const params = new URLSearchParams();
                if (beginIso) params.set('begin_time', beginIso);
                if (endIso) params.set('end_time', endIso);
                if (cursor) params.set('cursor', cursor);
                const url = `${base}?${params.toString()}`;
                const resp = await fetch(url, { headers });
                const json = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    console.warn('square payments fetch failed', resp.status, json);
                    break;
                }
                const batch = Array.isArray(json.payments) ? json.payments : [];
                payments.push(...batch);
                cursor = json.cursor || null;
                guard += 1;
            } while (cursor && guard < 50);
            return payments;
        }

        async function getSquareCustomerContact(accessToken, customerId, payment) {
            const contact = { email: null, phone: null };
            try {
                if (customerId) {
                    const cResp = await fetch(`https://connect.squareup.com/v2/customers/${customerId}`,
                        { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } });
                    if (cResp.ok) {
                        const cj = await cResp.json();
                        const c = cj?.customer || {};
                        contact.email = c?.email_address || null;
                        contact.phone = c?.phone_number || null;
                    }
                }
            } catch (_) { /* ignore */ }
            // Fallbacks from payment resource
            try { if (!contact.email && payment?.buyer_email_address) contact.email = payment.buyer_email_address; } catch(_){}
            try { if (!contact.phone && payment?.billing_address?.phone_number) contact.phone = payment.billing_address.phone_number; } catch(_){}
            return contact;
        }

        async function importPaymentsAndEnqueue({ uid, accessToken, beginIso, endIso }) {
            const ref = db.collection('businesses').doc(uid);
            const merchantSnap = await ref.get();
            if (!merchantSnap.exists) return { imported: 0, enqueued: 0 };
            const biz = merchantSnap.data() || {};
            const settings = biz.squareSettings || { autoSend: false, channel: 'email', delayMinutes: 0 };

            const payments = await fetchSquarePaymentsPaged(accessToken, beginIso, endIso);
            let imported = 0, enqueued = 0;
            for (const p of payments) {
                try {
                    if (!p || p.status !== 'COMPLETED') continue;
                    const payId = p.id;
                    if (!payId) continue;
                    // Idempotency: store import doc keyed by payment id
                    const impDoc = ref.collection('imports').doc(`square_${payId}`);
                    const existing = await impDoc.get();
                    if (existing.exists) continue;

                    // Write import marker first to avoid duplicate processing
                    await impDoc.set({ ts: new Date().toISOString(), source: 'square', payment: { id: payId, amount: p.amount_money || null } });
                    imported += 1;

                    if (!settings.autoSend) continue;
                    const customerId = p.customer_id || null;
                    const contact = await getSquareCustomerContact(accessToken, customerId, p);
                    if (!(contact.email || contact.phone)) continue;

                    // Build short link
                    const slug = biz.shortSlug || (biz.googlePlaceId ? biz.googlePlaceId : 'SETUP');
                    const shortLink = `${shortDomain}/${slug}`;
                    const delayMs = Math.max(0, (settings.delayMinutes || 0) * 60 * 1000);
                    const jobData = { channel: settings.channel || 'email', customer: contact, merchantUid: uid, shortLink };
                    if (reviewQueue) {
                        await reviewQueue.add('sendReviewRequest', jobData, { delay: delayMs, attempts: 1 });
                    } else {
                        setTimeout(() => { sendReviewRequest(jobData).catch(()=>{}); }, delayMs);
                    }
                    enqueued += 1;
                    await logEvent(uid, 'send_enqueued', { email: contact.email || null, phone: contact.phone || null, shortLink, via: 'backfill' });
                } catch (e) {
                    await logEvent(uid, 'import_error', { message: String(e && e.message || e) });
                }
            }
            // Update last sync timestamp
            try { await ref.set({ posLastSyncAt: new Date().toISOString() }, { merge: true }); } catch(_){}
            return { imported, enqueued };
        }

        // Trigger backfill for current merchant (default 30 days, max 90)
        app.post('/integrations/square/backfill', requireLogin, async (req, res) => {
            try {
                const uid = req.session.user.uid;
                const businessSnap = await db.collection('businesses').doc(uid).get();
                const biz = businessSnap.data() || {};
                if (!biz.square || !biz.square.access) return res.status(400).json({ error: 'not_connected' });
                const accessToken = await decryptString(biz.square.access);
                const days = Math.max(1, Math.min(90, parseInt((req.body && req.body.days) || (req.query && req.query.days) || '30', 10)));
                const endIso = new Date().toISOString();
                const beginIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
                const result = await importPaymentsAndEnqueue({ uid, accessToken, beginIso, endIso });
                return res.json({ ok: true, days, ...result });
            } catch (e) {
                console.error('square backfill error', e);
                return res.status(500).json({ error: 'server_error' });
            }
        });

        // Incremental sync from last sync time (fallback to 24h)
        app.post('/integrations/square/sync', requireLogin, async (req, res) => {
            try {
                const uid = req.session.user.uid;
                const ref = db.collection('businesses').doc(uid);
                const snap = await ref.get();
                const biz = snap.data() || {};
                if (!biz.square || !biz.square.access) return res.status(400).json({ error: 'not_connected' });
                const accessToken = await decryptString(biz.square.access);
                let beginIso = null;
                try {
                    const last = biz.posLastSyncAt ? new Date(biz.posLastSyncAt).getTime() : (Date.now() - 24*60*60*1000);
                    beginIso = new Date(Math.max(0, last - 60*60*1000)).toISOString(); // 1h overlap for safety
                } catch(_) { beginIso = new Date(Date.now() - 24*60*60*1000).toISOString(); }
                const endIso = new Date().toISOString();
                const result = await importPaymentsAndEnqueue({ uid, accessToken, beginIso, endIso });
                return res.json({ ok: true, ...result });
            } catch (e) {
                console.error('square sync error', e);
                return res.status(500).json({ error: 'server_error' });
            }
        });

    // --- 4. CONFIGURE THE SERVER (MIDDLEWARE) ---
    app.set('trust proxy', 1); // Trust first proxy for secure cookies in production
    app.set('view engine', 'ejs');
    app.set('view cache', false);
    // Serve static assets (global CSS, images, etc.)
    app.use(express.static('public'));
    // In development, disable HTTPS-forcing headers so Safari/Chrome don't upgrade to https://localhost
    if (isProduction) {
        app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: [
                        "'self'",
                        "'unsafe-inline'",
                        'https://www.googletagmanager.com',
                        'https://www.google-analytics.com',
                        'https://plausible.io',
                        'https://cdnjs.cloudflare.com',
                        'https://js.stripe.com',
                        'https://www.gstatic.com'
                    ],
                    imgSrc: ["'self'", 'data:', 'https:'],
                    styleSrc: ["'self'", "'unsafe-inline'", 'https:'],
                    fontSrc: ["'self'", 'https:', 'data:'],
                    frameSrc: [
                        "'self'",
                        'https://www.youtube.com',
                        'https://www.youtube-nocookie.com',
                        'https://js.stripe.com',
                        'https://checkout.stripe.com'
                    ],
                    childSrc: [
                        "'self'",
                        'https://js.stripe.com',
                        'https://checkout.stripe.com'
                    ],
                    formAction: [
                        "'self'",
                        'https://checkout.stripe.com'
                    ],
                    connectSrc: [
                        "'self'",
                        'https://plausible.io',
                        'https://www.google-analytics.com',
                        'https://identitytoolkit.googleapis.com',
                        'https://api.stripe.com',
                        'https://www.googleapis.com'
                    ],
                    objectSrc: ["'none'"],
                    upgradeInsecureRequests: []
                }
            },
            crossOriginEmbedderPolicy: false
        }));
    } else {
        app.use(helmet({
            contentSecurityPolicy: false, // removes upgrade-insecure-requests
            hsts: false,
            crossOriginEmbedderPolicy: false
        }));
    }
    app.use(compression());
    app.use(morgan('dev'));
    // cookieParser already mounted above
    const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;
    app.use(session({
        name: 'connect.sid',
        secret: process.env.SESSION_SECRET || 'a-super-secret-key-that-you-should-change',
        resave: false,
        saveUninitialized: false,
        proxy: true,
        cookie: {
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            domain: COOKIE_DOMAIN,
            maxAge: 30 * 24 * 60 * 60 * 1000
        }
    }));

    // Hydrate session from API cookie if present
    app.use(async (req, res, next) => {
        try {
            if (!req.session.user) {
                const raw = req.cookies && req.cookies.session;
                if (raw) {
                    try {
                        const jwt = require('jsonwebtoken');
                        const decoded = jwt.decode(raw);
                        if (decoded && decoded.sub) {
                            req.session.user = { uid: decoded.sub, email: null, displayName: null };
                        }
                    } catch(_) {}
                }
            }
        } catch(_) {}
        res.locals.user = req.session.user || null;
        next();
    });

    // Attach user access info (trial/active) for header visibility
    app.use(async (req, res, next) => {
        try {
            res.locals.userHasAccess = false;
            if (req.session && req.session.user) {
                const doc = await db.collection('businesses').doc(req.session.user.uid).get();
                if (doc.exists) {
                    const b = doc.data();
                    const isActive = b.subscriptionStatus === 'active';
                    const isTrial = b.subscriptionStatus === 'trial' && b.trialEndsAt && (new Date(b.trialEndsAt) > new Date());
                    res.locals.userHasAccess = !!(isActive || isTrial);
                }
            }
        } catch (_) { /* noop */ }
        next();
    });

    // Rate limiters
    const globalLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 200,
        standardHeaders: true,
        legacyHeaders: false,
    });
    app.use(globalLimiter);

    // Analytics config exposed to views
    app.locals.analytics = {
        provider: process.env.ANALYTICS_PROVIDER || null, // 'plausible' | 'ga'
        domain: process.env.ANALYTICS_DOMAIN || process.env.APP_BASE_URL || ''
    };

    // Stripe webhook must read raw body; mount BEFORE JSON parser
    app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
        try {
            const signature = req.headers['stripe-signature'];
            const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
            if (!webhookSecret) return res.status(400).send('Webhook secret not configured');
            let event;
            try {
                event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
            } catch (err) {
                console.error('❌ Webhook signature verification failed:', err.message);
                return res.status(400).send(`Webhook Error: ${err.message}`);
            }

            switch (event.type) {
                case 'checkout.session.completed': {
                    const sessionObj = event.data.object;
                    const customerId = sessionObj.customer;
                    const uid = sessionObj.client_reference_id || null;
                    if (uid) {
                        await db.collection('businesses').doc(uid).update({ subscriptionStatus: 'active', stripeCustomerId: customerId });
                        console.log('✅ Subscription activated via webhook (by uid):', uid);
                        try {
                            const bizSnap = await db.collection('businesses').doc(uid).get();
                            const b = bizSnap.data() || {};
                            const email = b.email || '';
                            if (email) {
                                const receipt = {
                                    orderNumber: sessionObj.id,
                                    date: new Date().toISOString(),
                                    description: 'Reviews & Marketing - Pro Plan (Billed Monthly)',
                                    amount: '$49.00',
                                    totalPaid: '$49.00',
                                    paidWith: (b.card && b.card.last4) ? `Card ending in ${b.card.last4}` : 'Card on file'
                                };
                                await sendEmail({
                                    to: email,
                                    template: 'Pro Plan Subscription & Receipt',
                                    data: { businessName: b.businessName || '', receipt, loginUrl: `${(process.env.APP_BASE_URL||'')}/dashboard` }
                                });
                            }
                        } catch (e) { console.warn('postmark pro receipt failed', e?.message || e); }
                    } else {
                    const snap = await db.collection('businesses').where('stripeCustomerId', '==', customerId).limit(1).get();
                    if (!snap.empty) {
                        const docRef = snap.docs[0].ref;
                        await docRef.update({ subscriptionStatus: 'active' });
                        console.log('✅ Subscription activated via webhook for customer:', customerId);
                        try {
                            const b = (await docRef.get()).data() || {};
                            const email = b.email || '';
                            if (email) {
                                const receipt = {
                                    orderNumber: sessionObj.id,
                                    date: new Date().toISOString(),
                                    description: 'Reviews & Marketing - Pro Plan (Billed Monthly)',
                                    amount: '$49.00',
                                    totalPaid: '$49.00',
                                    paidWith: (b.card && b.card.last4) ? `Card ending in ${b.card.last4}` : 'Card on file'
                                };
                                await sendEmail({
                                    to: email,
                                    template: 'Pro Plan Subscription & Receipt',
                                    data: { businessName: b.businessName || '', receipt, loginUrl: `${(process.env.APP_BASE_URL||'')}/dashboard` }
                                });
                            }
                        } catch (e) { console.warn('postmark pro receipt (no uid) failed', e?.message || e); }
                        }
                    }
                    break;
                }
                case 'customer.subscription.deleted':
                case 'customer.subscription.updated': {
                    const subscription = event.data.object;
                    // Ensure business is marked inactive if canceled
                    const customerId = subscription.customer;
                    const status = subscription.status === 'active' ? 'active' : 'canceled';
                    const snap = await db.collection('businesses').where('stripeCustomerId', '==', customerId).limit(1).get();
                    if (!snap.empty) {
                        const docRef = snap.docs[0].ref;
                        await docRef.update({ subscriptionStatus: status });
                        console.log('ℹ️ Subscription status updated via webhook:', status);
                    }
                    break;
                }
                default:
                    // no-op
                    break;
            }
            res.json({ received: true });
        } catch (error) {
            console.error('❌ Error handling Stripe webhook:', error);
            res.status(500).send('Server error');
        }
    });

    // Now enable parsers for the rest of the app
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // CSRF protection (opt-in per route) — cookie-based secret for stability
    const csrfProtection = csurf({ cookie: { key: '_csrf', httpOnly: true, sameSite: 'lax', secure: isProduction } });
    // Friendly CSRF error handler
    app.use((err, req, res, next) => {
        if (err && err.code === 'EBADCSRFTOKEN') {
            const token = (typeof req.csrfToken === 'function') ? (function(){ try { return req.csrfToken(); } catch(_) { return ''; } })() : '';
            const path = req.path || '';
            if (path.startsWith('/login') || path.startsWith('/auth/login')) {
                return res.status(403).render('login', { csrfToken: token, error: 'Security check failed. Please try again.', user: req.session.user || null });
            }
            if (path.startsWith('/signup') || path.startsWith('/auth/signup')) {
                return res.status(403).render('signup', { csrfToken: token, error: 'Security check failed. Please try again.', user: req.session.user || null });
            }
            if (path.startsWith('/forgot-password') || path.startsWith('/auth/forgot-password')) {
                return res.status(403).render('forgot-password', { csrfToken: token, user: req.session.user || null });
            }
            if (path.startsWith('/reset-password') || path.startsWith('/auth/reset-password')) {
                const t = req.body && req.body.token ? req.body.token : (req.query && req.query.token ? req.query.token : '');
                return res.status(403).render('reset-password', { csrfToken: token, token: t, error: 'Security check failed. Please try again.', user: req.session.user || null });
            }
            return res.status(403).send('Form expired. Refresh and try again.');
        }
        next(err);
    });

    // legacy requireLogin moved earlier; keep stub to avoid duplicate definition

    // --- 5. DEFINE THE ROUTES (THE "URLS") ---
    // Preferred explicit base URL for links shown in the UI (dashboard public link, success/cancel URLs)

    // AUTH ROUTES
    app.get('/healthz', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'development' }));

    // Lightweight admin guard based on configured emails
    const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
        .split(',')
        .map(s => s.trim().toLowerCase())
        .filter(Boolean);
    const requireAdmin = (req, res, next) => {
        try {
            if (!(req.session && req.session.user)) {
                return res.status(401).send('unauthenticated');
            }
            const email = ((req.session.user && req.session.user.email) || '').toLowerCase();
            if (!email || !ADMIN_EMAILS.length || !ADMIN_EMAILS.includes(email)) {
                return res.status(403).send('forbidden');
            }
            return next();
        } catch (_) {
            return res.status(403).send('forbidden');
        }
    };

    // Ops: status overview (admin-only)
    app.get('/ops/status', requireLogin, requireAdmin, async (req, res) => {
        const result = { ok: true };
        const checks = {};
        try {
            checks.env = process.env.NODE_ENV || 'development';
            checks.time = new Date().toISOString();
            checks.slackConfigured = !!(process.env.SLACK_WEBHOOK_URL);
            checks.redisReady = !!(typeof reviewQueue !== 'undefined' && reviewQueue);
            checks.firestore = 'unknown';
            try {
                const testSnap = await db.collection('businesses').limit(1).get();
                checks.firestore = testSnap ? 'ok' : 'unknown';
            } catch (e) {
                checks.firestore = 'error';
            }
            checks.googleMapsKeyPresent = !!process.env.GOOGLE_MAPS_API_KEY;
            checks.kmsKeyConfigured = !!process.env.KMS_KEY_ID;
            checks.postmarkConfigured = !!process.env.POSTMARK_SERVER_TOKEN;
            checks.twilioConfigured = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN);
            checks.squareConfigured = !!(process.env.SQUARE_APP_ID && process.env.SQUARE_APP_SECRET);
            checks.authApiBase = (process.env.API_GATEWAY_BASE_URL || process.env.AUTH_API_BASE || '') || null;
            return res.json({ ok: true, checks });
        } catch (e) {
            return res.status(500).json({ ok: false, error: 'status_error' });
        }
    });

    // Ops: manual Slack test alert (admin-only)
    app.post('/ops/test-alert', requireLogin, requireAdmin, async (req, res) => {
        try {
            const userEmail = (req.session.user && req.session.user.email) || 'unknown';
            const env = process.env.NODE_ENV || 'development';
            await notifyAlert('Manual test alert', { env, userEmail, at: new Date().toISOString() });
            return res.json({ ok: true });
        } catch (e) {
            return res.status(500).json({ ok: false });
        }
    });
    // Simple in-memory cache for homepage stats (15 minutes)
    let __homepageStatsCache = { at: 0, data: { avg: '4.8', convPercent: '62' } };
    app.get('/', csrfProtection, async (req, res) => {
        try {
            const now = Date.now();
            if (now - __homepageStatsCache.at > 15 * 60 * 1000) {
                const ninetyAgoIso = new Date(now - 90 * 24 * 60 * 60 * 1000).toISOString();
                const cg = await db.collectionGroup('feedback').where('createdAt', '>=', ninetyAgoIso).get();
                let total = 0; let sum = 0; let five = 0;
                cg.forEach(doc => {
                    const d = doc.data();
                    const r = Number(d.rating) || 0;
                    if (r >= 1 && r <= 5) { total++; sum += r; if (r === 5) five++; }
                });
                const avg = total ? (sum / total).toFixed(2) : '0.00';
                const convPercent = total ? Math.round((five / total) * 100).toString() : '0';
                __homepageStatsCache = { at: now, data: { avg, convPercent } };
            }
            return res.render('index', {
                csrfToken: req.csrfToken(),
                title: 'Reviews & Marketing • Turn happy customers into 5‑star reviews',
                user: req.session.user || null,
                homepageStats: __homepageStatsCache.data,
            });
        } catch (e) {
            console.error('home stats error', e);
            return res.render('index', { csrfToken: req.csrfToken(), title: 'Reviews & Marketing • Turn happy customers into 5‑star reviews', user: req.session.user || null, homepageStats: { avg: '4.8', convPercent: '62' } });
        }
    });
    app.get('/features', csrfProtection, (req, res) => res.render('features', { csrfToken: req.csrfToken(), title: 'Features • Reviews & Marketing', user: req.session.user || null }));
    app.get('/pricing', csrfProtection, async (req, res) => {
        let subscriptionStatus = null;
        let trialEndsAt = null;
        let isActive = false;
        let validTrial = false;
        try {
        if (req.session.user) {
                const doc = await db.collection('businesses').doc(req.session.user.uid).get();
                if (doc.exists) {
                    const data = doc.data() || {};
                    subscriptionStatus = data.subscriptionStatus || null;
                    trialEndsAt = data.trialEndsAt || null;
                    isActive = subscriptionStatus === 'active';
                    validTrial = subscriptionStatus === 'trial' && trialEndsAt && (new Date(trialEndsAt) > new Date());
                }
            }
        } catch (_) { /* ignore */ }
        res.render('pricing', { csrfToken: req.csrfToken(), title: 'Pricing • Reviews & Marketing', user: req.session.user || null, subscriptionStatus, isActive, validTrial, trialEndsAt });
    });
    app.get('/privacy', csrfProtection, (req, res) => res.render('privacy', { csrfToken: req.csrfToken(), title: 'Privacy Policy • Reviews & Marketing', user: req.session.user || null }));

    // Phase 4.2: BFF auth POST routes → API Gateway (custom auth backend)
    const AUTH_API_BASE = process.env.API_GATEWAY_BASE_URL || process.env.AUTH_API_BASE || '';
    function getAuthApiBase(){
        if (AUTH_API_BASE) return AUTH_API_BASE.replace(/\/$/, '');
        // Fallback to known default used during setup (best-effort)
        return 'https://becb9v5qw8.execute-api.us-east-1.amazonaws.com/prod';
    }
    
    app.post('/auth/signup', csrfProtection, async (req, res) => {
        try {
            const { businessName, email, password, confirmPassword } = req.body || {};
            if (!businessName || !email || !password || !confirmPassword) {
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
                return res.status(400).render('signup', { csrfToken: token, error: 'All fields are required.', user: req.session.user || null });
            }
            if (password !== confirmPassword) {
                const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
                return res.status(400).render('signup', { csrfToken: token, error: 'Passwords do not match.', user: req.session.user || null });
            }
            const r = await fetch(getAuthApiBase() + '/register', {
                method: 'POST', headers: { 'Content-Type':'application/json', 'Accept':'application/json' },
                body: JSON.stringify({ businessName, email, password })
            });
            if (r.ok) {
                return res.redirect('/login?registered=1');
            }
            let msg = 'Could not create account.';
            try { const j = await r.json(); if (j && j.error) msg = String(j.error); } catch(_){ }
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            return res.status(r.status || 400).render('signup', { csrfToken: token, error: msg, user: req.session.user || null });
        } catch (e) {
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            return res.status(500).render('signup', { csrfToken: token, error: 'Unexpected error. Try again.', user: req.session.user || null });
        }
    });
    
    app.post('/auth/login', csrfProtection, async (req, res) => {
        try {
            const { email, password } = req.body || {};
            if (!email || !password) {
                const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
                return res.status(400).render('login', { csrfToken: token, error: 'Missing email or password.', user: req.session.user || null });
            }
            const r = await fetch(getAuthApiBase() + '/login', {
                method: 'POST', headers: { 'Content-Type':'application/json', 'Accept':'application/json' },
                body: JSON.stringify({ email, password }),
                redirect: 'manual'
            });
            const rawSetCookie = r.headers.get('set-cookie');
            if (rawSetCookie) {
                try {
                    // Re-issue cookie for our domain: strip any Domain attr, enforce security attrs
                    const sanitize = (val) => {
                        const parts = String(val).split(';').map(s => s.trim()).filter(Boolean).filter(p => !/^Domain=/i.test(p));
                        if (!parts.some(p => /^Path=/i.test(p))) parts.push('Path=/');
                        if (!parts.some(p => /^SameSite=/i.test(p))) parts.push('SameSite=Lax');
                        if (!parts.some(p => /^HttpOnly$/i.test(p))) parts.push('HttpOnly');
                        if (process.env.NODE_ENV === 'production' && !parts.some(p => /^Secure$/i.test(p))) parts.push('Secure');
                        if (process.env.COOKIE_DOMAIN) parts.push(`Domain=${process.env.COOKIE_DOMAIN}`);
                        return parts.join('; ');
                    };
                    // Some gateways return multiple Set-Cookie entries in a single header when using fetch
                    const cookies = rawSetCookie.includes(',') && !/Expires=/i.test(rawSetCookie)
                        ? rawSetCookie.split(',')
                        : [rawSetCookie];
                    const sanitized = cookies.map(sanitize);
                    res.setHeader('Set-Cookie', sanitized);
                } catch(_) {}
            }
            if (r.ok) {
                // Bridge session for current app until full migration: decode JWT 'session' cookie to set req.session.user
                let bridgedUserId = null;
                try { const data = await r.clone().json(); if (data && data.userId) bridgedUserId = data.userId; } catch(_) {}
                try {
                    const m = rawSetCookie && rawSetCookie.match(/session=([^;]+)/);
                    if (!bridgedUserId && m && m[1]) {
                        const jwt = require('jsonwebtoken');
                        const decoded = jwt.decode(m[1]);
                        const sub = decoded && decoded.sub ? decoded.sub : null;
                        bridgedUserId = sub || bridgedUserId;
                    }
                    // If we still could not derive a user id from cookie (opaque session cookie), ask the Auth API
                    if (!bridgedUserId) {
                        try {
                            const sessionPair = (rawSetCookie && rawSetCookie.match(/session=([^;]+)/)) ? `session=${rawSetCookie.match(/session=([^;]+)/)[1]}` : null;
                            if (sessionPair) {
                                const meResp = await fetch(getAuthApiBase() + '/me', {
                                    method: 'GET',
                                    headers: { 'Accept': 'application/json', 'Cookie': sessionPair }
                                });
                                if (meResp.ok) {
                                    const meJson = await meResp.json().catch(()=>({}));
                                    bridgedUserId = meJson && (meJson.userId || meJson.sub || meJson.id || meJson.uid) || null;
                                }
                            }
                        } catch(_) { /* ignore */ }
                    }
                    if (bridgedUserId) {
                        // Ensure a minimal business doc exists for this UID so dashboard can load
                        try {
                            const ref = db.collection('businesses').doc(bridgedUserId);
                            const snap = await ref.get();
                            if (!snap.exists) {
                                await ref.set({
                                    businessName: '',
                                    email: (email || '').toLowerCase(),
                                    googlePlaceId: null,
                                    stripeCustomerId: null,
                                    subscriptionStatus: 'none',
                createdAt: new Date().toISOString(),
            });
                            }
                        } catch (_) { /* non-fatal */ }
                        req.session.user = { uid: bridgedUserId, email: (email || '').toLowerCase(), displayName: null };
                        return req.session.save((err) => { if (err) console.warn('session save error (auth bridge):', err); res.setHeader('Cache-Control','no-store'); return res.redirect('/dashboard'); });
                    }
                } catch (_) { /* ignore bridge errors */ }
                res.setHeader('Cache-Control','no-store');
            return res.redirect('/dashboard');
            }
            let msg = 'Invalid email or password.';
            try { const j = await r.json(); if (j && j.error) msg = String(j.error); } catch(_){ }
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            return res.status(200).render('login', { csrfToken: token, error: msg, user: req.session.user || null });
        } catch (e) {
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            return res.status(500).render('login', { csrfToken: token, error: 'Unexpected error. Try again.', user: req.session.user || null });
        }
    });
    
    app.post('/auth/forgot-password', csrfProtection, async (req, res) => {
        try {
            const { email } = req.body || {};
            if (!email) {
                const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
                return res.status(400).render('forgot-password', { csrfToken: token, user: req.session.user || null });
            }
            await fetch(getAuthApiBase() + '/forgot-password', {
                method: 'POST', headers: { 'Content-Type':'application/json', 'Accept':'application/json' },
                body: JSON.stringify({ email })
            }).catch(()=>{});
            return res.redirect('/forgot-password?sent=1');
        } catch (_) {
            return res.redirect('/forgot-password?sent=1');
        }
    });
    
    app.post('/auth/reset-password', csrfProtection, async (req, res) => {
        try {
            const { token: resetToken, newPassword, confirmNewPassword, email } = req.body || {};
            if (!resetToken || !newPassword || !confirmNewPassword) return res.status(400).send('Missing fields');
            if (newPassword !== confirmNewPassword) {
                const viewToken = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
                return res.status(400).render('reset-password', { csrfToken: viewToken, token: resetToken, email: email || '', user: req.session.user || null });
            }
            const payload = email ? { token: resetToken, newPassword, email } : { token: resetToken, newPassword };
            const r = await fetch(getAuthApiBase() + '/reset-password', {
                method: 'POST', headers: { 'Content-Type':'application/json', 'Accept':'application/json' },
                body: JSON.stringify(payload)
            });
            if (r.ok) return res.redirect('/login?reset=1');
            const viewToken = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            let msg = 'Could not reset password.';
            try { const j = await r.json(); if (j && j.error) msg = String(j.error); } catch(_){ }
            return res.status(400).render('reset-password', { csrfToken: viewToken, token: resetToken, email: email || '', error: msg, user: req.session.user || null });
        } catch (e) {
            const viewToken = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            return res.status(500).render('reset-password', { csrfToken: viewToken, token: (req.body && req.body.token) || '', email: (req.body && req.body.email) || '', error: 'Unexpected error. Try again.', user: req.session.user || null });
        }
    });
    
    app.post('/auth/logout', csrfProtection, (req, res) => {
        try { if (req.session) req.session.destroy(()=>{}); } catch(_){ }
        res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax');
        return res.redirect('/login');
    });
    // Recovery: GET /logout clears cookies without CSRF (useful to break redirect loops)
    app.get('/logout', (req, res) => {
        try { if (req.session) req.session.destroy(()=>{}); } catch(_){ }
        res.setHeader('Set-Cookie', [
            'session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax',
            'connect.sid=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax'
        ]);
        return res.redirect('/login');
    });
    // Phase 4.1: Auth view routes (GET)
    app.get('/signup', csrfProtection, (req, res) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        res.render('signup', { csrfToken: token, error: null, user: req.session.user || null });
    });
    app.get('/login', csrfProtection, (req, res) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        // Always render the login form; avoid auto-redirects to prevent loops
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        const q = req.query || {};
        let hint = null;
        if (q.registered) hint = 'Account created! We\'ve emailed a verification link. Open it to verify your email, then log in.';
        else if (q.verified) hint = 'Your email is verified. You can now log in.';
        else if (q.reset) hint = 'Your password was updated. Please log in.';
        res.render('login', { csrfToken: token, error: null, hint, user: req.session.user || null });
    });
    app.get('/forgot-password', csrfProtection, (req, res) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        const sent = !!(req.query && req.query.sent);
        res.render('forgot-password', { csrfToken: token, sent, user: req.session.user || null });
    });
    app.get('/reset-password', csrfProtection, (req, res) => {
        const tokenParam = req.query && req.query.token;
        const emailParam = req.query && req.query.email;
        if (!tokenParam) return res.status(400).send('Invalid or missing reset token.');
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        res.render('reset-password', { csrfToken: token, token: tokenParam, email: emailParam || '', user: req.session.user || null });
    });
    app.get('/dashboard', requireAccess, csrfProtection, async (req, res) => {
        try {
            // Force no-cache headers to prevent browser caching issues
            res.set({
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            });
            
            const uid = getUserIdFromRequest(req);
            console.log(`[DASHBOARD START] uid=${uid}`);
            let knownPlaceId = null;
            
            // Force fresh read from Firestore - no caching
            let businessDoc = await db.collection('businesses').doc(uid).get();
            
            // Fallback: some accounts may have business docs keyed differently. Try email lookup.
            if (!businessDoc.exists) {
                const email = (req.session.user && req.session.user.email) || null;
                console.log(`[DASHBOARD FALLBACK] uid doc not found, trying email=${email}`);
                if (email) {
                    const q = await db.collection('businesses').where('email','==', email).limit(1).get();
                    if (!q.empty) {
                        businessDoc = q.docs[0];
                        console.log(`[DASHBOARD FALLBACK] found by email, docId=${businessDoc.id}`);
                    }
                }
            }
            if (!businessDoc.exists) throw new Error('No business data found.');
            const businessRef = db.collection('businesses').doc(businessDoc.id);
            knownPlaceId = (businessDoc.data() || {}).googlePlaceId || null;
            // Inputs for analytics (Pro can filter; Free defaults)
            const isPro = (businessDoc.data().subscriptionStatus === 'active');
            const now = Date.now();
            const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);
            const requestedRange = (req.query && req.query.range) ? String(req.query.range) : '';
            let cutoffMs = null;
            if (isPro) {
                if (requestedRange === '7d') cutoffMs = now - (7 * 24 * 60 * 60 * 1000);
                else if (requestedRange === '30d') cutoffMs = now - (30 * 24 * 60 * 60 * 1000);
                else if (requestedRange === '90d') cutoffMs = now - (90 * 24 * 60 * 60 * 1000);
                else if (requestedRange === 'all' || requestedRange === '') cutoffMs = null;
            } else {
                cutoffMs = thirtyDaysAgo; // Free always 30 days
            }
            const selectedRange = isPro ? (requestedRange || 'all') : '30d';
            // Fetch reviews with index, fallback to indexless query if needed
            let feedback = [];
            console.log(`[PIPELINE-READ] Fetching data for loggedInUserId: ${uid}`);
            
            try {
                const feedbackSnapshot = await db.collection('reviews')
                    .where('userId', '==', uid)
                    .orderBy('createdAt', 'desc')
                    .get();
                feedback = feedbackSnapshot.docs.map(doc => doc.data());
                console.log(`[PIPELINE-READ] SUCCESS: Found ${feedback.length} reviews using indexed query.`);
            } catch (e) {
                try {
                    console.warn('[PIPELINE-READ] Indexed query failed, falling back to indexless fetch:', e && (e.code || e.message || String(e)));
                    if (e.message && e.message.includes('FAILED_PRECONDITION')) {
                        console.error('[PIPELINE-READ] FAILED_PRECONDITION: The required composite index (userId asc, createdAt desc) is missing or building. Check Firebase Console.');
                    }
                    
                    const fallbackSnap = await db.collection('reviews')
                        .where('userId', '==', uid)
                        .get();
                    feedback = fallbackSnap.docs.map(d => ({ id: d.id, ...d.data() }));
                    // Sort by createdAt desc client-side
                    feedback.sort((a, b) => {
                        const ta = a.createdAt && a.createdAt.toDate ? a.createdAt.toDate().getTime() : new Date(a.createdAt || 0).getTime();
                        const tb = b.createdAt && b.createdAt.toDate ? b.createdAt.toDate().getTime() : new Date(b.createdAt || 0).getTime();
                        return tb - ta;
                    });
                    console.log(`[PIPELINE-READ] Fallback query found ${feedback.length} reviews.`);
                } catch (e2) {
                    console.warn('[PIPELINE-READ] Indexless fallback also failed:', e2 && (e2.code || e2.message || String(e2)));
                    feedback = [];
                }
            }
            if (cutoffMs) {
                feedback = feedback.filter(f => { try { return (new Date(f.createdAt).getTime()) >= cutoffMs; } catch(_) { return false; } });
            }

            // Basic analytics
            const total = feedback.length;
            const counts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
            let sum = 0; let conversions = 0;
            feedback.forEach(f => {
                const r = Number(f.rating) || 0;
                if (r >= 1 && r <= 5) { counts[r]++; sum += r; }
                if (r === 5 && (f.type === 'positive' || f.type === 'contact')) conversions++;
            });
            const avg = total ? (sum / total).toFixed(2) : '0.00';
            
            console.log(`[PIPELINE-READ] SUCCESS: Found ${feedback.length} reviews. Stats count: ${total}.`);

            // Billing details (renewal / cancel info)
            const businessData = businessDoc.data();
            let billing = null;
            if (businessData.stripeCustomerId) {
                try {
                    const subs = await stripe.subscriptions.list({ customer: businessData.stripeCustomerId, status: 'all', limit: 1 });
                    if (subs.data && subs.data.length) {
                        const sub = subs.data[0];
                        const end = sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
                        billing = {
                            status: sub.status,
                            cancelAtPeriodEnd: !!sub.cancel_at_period_end,
                            currentPeriodEnd: end,
                            planName: (sub.items && sub.items.data[0] && (sub.items.data[0].price.nickname || sub.items.data[0].price.id)) || 'Pro',
                        };
                    }
                    // payment method on file
                    const cust = await stripe.customers.retrieve(businessData.stripeCustomerId);
                    let pmId = cust.invoice_settings && cust.invoice_settings.default_payment_method;
                    let cardInfo = null;
                    if (pmId) {
                        const pm = await stripe.paymentMethods.retrieve(pmId);
                        if (pm && pm.card) {
                            cardInfo = { brand: pm.card.brand, last4: pm.card.last4, exp: `${pm.card.exp_month}/${pm.card.exp_year}` };
                        }
                    } else {
                        const pms = await stripe.paymentMethods.list({ customer: businessData.stripeCustomerId, type: 'card', limit: 1 });
                        if (pms.data && pms.data.length && pms.data[0].card) {
                            const c = pms.data[0].card;
                            cardInfo = { brand: c.brand, last4: c.last4, exp: `${c.exp_month}/${c.exp_year}` };
                        }
                    }
                    if (billing) billing.card = cardInfo;
                } catch (e) {
                    console.warn('Stripe subscription lookup failed:', e.message);
                }
            }
            // Onboarding checklist
            const bizData = businessDoc.data() || {};
            console.log(`[DASHBOARD READ] uid=${req.session.user.uid}, docId=${businessDoc.id}, googlePlaceId=${bizData.googlePlaceId}, hasGooglePlaceId=${!!bizData.googlePlaceId}`);
            let posConnected = !!(bizData.posConnection && bizData.posConnection.isConnected);
            if (!posConnected && bizData.square && bizData.square.access) posConnected = true;
            let sentFirst = false;
            let recentEvents = [];
            try {
                const es = await businessRef.collection('events').orderBy('ts', 'desc').limit(25).get();
                sentFirst = es.docs.some(d => {
                    const t = (d.data() || {}).type || '';
                    return t === 'send_email' || t === 'send_sms';
                });
                recentEvents = es.docs.map(d => {
                    const e = d.data() || {};
                    return { type: e.type || 'event', ts: e.ts || new Date().toISOString(), payload: e.payload || {} };
                });
            } catch(_) {}
            const onboarding = {
                hasPlaceId: !!bizData.googlePlaceId,
                hasShortLink: !!(bizData.shortSlug || bizData.googlePlaceId),
                posConnected,
                sentFirst
            };
            const onboardingDismissed = !!bizData.onboardingDismissed;
            const squareSettings = bizData.squareSettings || { autoSend: false, delayMinutes: 0, channel: 'email' };

            // Trial days left for UI
            let trialDaysLeft = null;
            try {
                const t = businessDoc.data()?.trialEndsAt;
                if (t) {
                    const ms = new Date(t).getTime() - Date.now();
                    if (ms > 0) trialDaysLeft = Math.ceil(ms / (24*60*60*1000));
                }
            } catch(_) {}

            // Force a fresh calculation of hasGooglePlaceId right before render
            const currentGooglePlaceId = bizData.googlePlaceId || null;
            const hasGooglePlaceId = !!(currentGooglePlaceId && currentGooglePlaceId.trim().length > 0);
            
            console.log(`[DASHBOARD RENDER] hasGooglePlaceId=${hasGooglePlaceId}, googlePlaceId="${currentGooglePlaceId}"`);

            res.render('dashboard', {
                business: businessDoc.data(),
                user: req.session.user,
                feedback: feedback,
                appUrl: appUrl, // Pass the appUrl to the dashboard
                csrfToken: req.csrfToken(),
                analytics: { total, avg, counts, conversions, planTier: isPro ? 'pro' : 'free' },
                billing,
                onboarding,
                onboardingDismissed,
                hasGooglePlaceId: hasGooglePlaceId,
                squareSettings,
                recentEvents,
                trialDaysLeft,
                selectedRange,
                pageError: req.query && req.query.e ? decodeURIComponent(req.query.e) : null
            });
        } catch (error) {
            console.error("❌ Error fetching dashboard data (temporary fallback shown):", error);
            // Render dashboard shell with placeholders while Firestore index builds
            try {
                const placeholderAnalytics = { total: 0, avg: '0.00', counts: { 1:0, 2:0, 3:0, 4:0, 5:0 }, conversions: 0 };
                return res.render('dashboard', {
                    business: { businessName: '', email: (req.session.user && req.session.user.email) || '', subscriptionStatus: 'none', googlePlaceId: knownPlaceId },
                    user: req.session.user,
                    feedback: [],
                    appUrl: appUrl,
                    csrfToken: req.csrfToken(),
                    analytics: placeholderAnalytics,
                    billing: null,
                    onboarding: { hasPlaceId: !!knownPlaceId, hasShortLink: !!knownPlaceId, posConnected: false, sentFirst: false },
                    onboardingDismissed: false,
                    hasGooglePlaceId: !!(knownPlaceId && String(knownPlaceId).trim().length > 0),
                    squareSettings: { autoSend: false, delayMinutes: 0, channel: 'email' },
                    recentEvents: [],
                    pageError: null
                });
            } catch (_) {
                return res.redirect('/login');
            }
        }
    });

    // Simple admin dashboard (owner-only) to view customers and issue refunds
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
    app.get('/admin', async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
            const snap = await db.collection('businesses').limit(200).get();
            const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));
            res.render('admin', { items, user: req.session.user || null });
        } catch (e) {
            console.error('Admin error', e); res.status(500).send('Admin error');
        }
    });

    // Admin: metrics for a business
    app.get('/admin/metrics/:id', async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'forbidden' });
            const businessId = req.params.id;
            const snap = await db.collection('businesses').doc(businessId).collection('feedback').get();
            const feedback = snap.docs.map(d => d.data());
            const total = feedback.length;
            let sum = 0; let conversions = 0;
            feedback.forEach(f => {
                const r = Number(f.rating) || 0;
                if (r >= 1 && r <= 5) sum += r;
                if (r === 5 && (f.type === 'positive' || f.type === 'contact')) conversions++;
            });
            const avg = total ? (sum / total).toFixed(2) : '0.00';
            res.json({ total, avg, conversions });
        } catch (e) { console.error('metrics error', e); res.status(500).json({ error: 'server' }); }
    });

    // Admin: impersonate a business to view dashboard
    app.post('/admin/impersonate/:id', express.urlencoded({ extended: true }), async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
            const id = req.params.id;
            const doc = await db.collection('businesses').doc(id).get();
            if (!doc.exists) return res.status(404).send('Not found');
            const data = doc.data();
            req.session.user = { uid: id, email: data.email || '', displayName: data.businessName || '' };
            res.redirect('/dashboard');
        } catch (e) { console.error('impersonate error', e); res.status(500).send('Server error'); }
    });

    app.get('/admin/impersonate/:id', async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
            const id = req.params.id;
            const doc = await db.collection('businesses').doc(id).get();
            if (!doc.exists) return res.status(404).send('Not found');
            const data = doc.data();
            req.session.user = { uid: id, email: data.email || '', displayName: data.businessName || '' };
            res.redirect('/dashboard');
        } catch (e) { console.error('impersonate error', e); res.status(500).send('Server error'); }
    });

    // Admin: open Stripe billing portal for a business
    app.get('/admin/manage-subscription/:id', async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
            const id = req.params.id;
            const doc = await db.collection('businesses').doc(id).get();
            if (!doc.exists) return res.status(404).send('Not found');
            const customerId = doc.data().stripeCustomerId;
            if (!customerId) return res.status(400).send('Missing Stripe customer');
            const portalSession = await stripe.billingPortal.sessions.create({
                customer: customerId,
                return_url: `${appUrl}/admin`
            });
            res.redirect(303, portalSession.url);
        } catch (e) { console.error('admin portal', e); res.status(500).send('Server error'); }
    });

    // Terms of Service
    app.get('/terms', (req, res) => {
        try {
            res.render('terms');
        } catch (e) { res.status(500).send('Server error'); }
    });

    app.post('/admin/refund', express.urlencoded({extended:true}), async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
            const { chargeId } = req.body || {};
            if (!chargeId) return res.status(400).send('Missing chargeId');
            const refund = await stripe.refunds.create({ charge: chargeId });
            res.json({ ok: true, refund });
        } catch (e) { console.error('Refund error', e); res.status(500).json({ ok:false }); }
    });

    app.post('/api/settings/dismiss-onboarding', requireLogin, csrfProtection, async (req, res) => {
        try {
            await db.collection('businesses').doc(req.session.user.uid).set({
                onboardingDismissed: true
            }, { merge: true });
            res.json({ ok: true });
        } catch (error) {
            console.error("❌ Error dismissing onboarding:", error);
            res.status(500).json({ ok: false });
        }
    });

    // Weekly reports configuration
    app.post('/report-settings', requireLogin, csrfProtection, async (req, res) => {
        try {
            const { enabled, frequency, email } = req.body || {};
            const ref = db.collection('businesses').doc(req.session.user.uid);
            await ref.set({ reportSettings: { enabled: !!enabled, frequency: frequency || 'weekly', email: email || null, updatedAt: new Date().toISOString() } }, { merge: true });
            res.redirect('/dashboard');
        } catch (e) { console.error('report-settings', e); res.status(500).send('server'); }
    });

    // PAYMENT ROUTES
    // Analytics export (Pro only)
    app.get('/api/analytics/export.csv', requireLogin, async (req, res) => {
        try {
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const doc = await ref.get();
            const data = doc.data() || {};
            if (data.subscriptionStatus !== 'active') return res.status(403).send('upgrade');
            const snap = await ref.collection('feedback').orderBy('createdAt', 'desc').get();
            const rows = [['createdAt','name','email','phone','rating','type','feedback']];
            snap.docs.forEach(d => {
                const f = d.data() || {};
                rows.push([
                    new Date(f.createdAt || '').toISOString(),
                    f.name || '', f.email || '', f.phone || '',
                    String(f.rating || ''), f.type || '', (f.feedback || '').replace(/\n/g,' ')
                ]);
            });
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename="analytics.csv"');
            res.send(rows.map(r => r.map(v => '"' + String(v).replace(/"/g,'""') + '"').join(',')).join('\n'));
        } catch (e) { console.error('export csv', e); res.status(500).send('server'); }
    });

    app.get('/api/analytics/export.pdf', requireLogin, async (req, res) => {
        try {
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const doc = await ref.get();
            const data = doc.data() || {};
            if (data.subscriptionStatus !== 'active') return res.status(403).send('upgrade');
            const snap = await ref.collection('feedback').orderBy('createdAt', 'desc').get();
            const feedback = snap.docs.map(d => d.data());
            let total = feedback.length, sum = 0, conversions = 0;
            const counts = { 1:0,2:0,3:0,4:0,5:0 };
            feedback.forEach(f => { const r = Number(f.rating)||0; if (r>=1&&r<=5){ counts[r]++; sum+=r; } if (r===5 && (f.type==='positive'||f.type==='contact')) conversions++; });
            const avg = total ? (sum/total).toFixed(2) : '0.00';
            res.setHeader('Content-Type','application/pdf');
            res.setHeader('Content-Disposition','attachment; filename="analytics.pdf"');
            const docPdf = new PDFDocument({ size:'LETTER', margin:48 });
            docPdf.pipe(res);
            docPdf.fontSize(20).text('Analytics Report', { align:'left' });
            docPdf.moveDown(0.5).fontSize(12).fillColor('#555').text(`Generated: ${new Date().toLocaleString()}`);
            docPdf.moveDown();
            docPdf.fillColor('#000').fontSize(14).text('Summary');
            docPdf.moveDown(0.5).fontSize(12).fillColor('#333')
              .text(`Total feedback: ${total}`)
              .text(`Average rating: ${avg}`)
              .text(`5★ conversions: ${conversions}`);
            docPdf.moveDown().fontSize(14).fillColor('#000').text('Distribution');
            Object.keys(counts).sort().forEach(k => { docPdf.fontSize(12).fillColor('#333').text(`${k}★: ${counts[k]}`); });
            docPdf.end();
        } catch (e) { console.error('export pdf', e); res.status(500).send('server'); }
    });

    // --- Debug: isolated database write test page ---
    app.get('/debug/save-test', requireLogin, csrfProtection, async (req, res) => {
        try {
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const snap = await ref.get();
            const testData = snap.exists ? ((snap.data() || {}).testData || null) : null;
            return res.render('debug-save-test', { csrfToken: req.csrfToken(), user: req.session.user || null, testData });
        } catch (e) {
            console.error('debug save-test read error', e && (e.stack || e.message || e));
            return res.status(500).send('debug page error');
        }
    });
    app.get('/api/debug/read-test', requireLogin, async (req, res) => {
        try {
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const snap = await ref.get();
            const testData = snap.exists ? ((snap.data() || {}).testData || null) : null;
            return res.json({ ok: true, testData });
        } catch (e) {
            return res.status(500).json({ ok: false, error: String(e && (e.stack || e.message || e)) });
        }
    });
    app.post('/api/debug/save-test', requireLogin, csrfProtection, async (req, res) => {
        try {
            const body = req.body || {};
            const value = (typeof body.value === 'string') ? body.value : (typeof body.testData === 'string' ? body.testData : '');
            const toSave = String(value);
            const ref = db.collection('businesses').doc(req.session.user.uid);
            await ref.set({ testData: toSave, updatedAt: new Date().toISOString() }, { merge: true });
            // Verify write
            const verify = await ref.get();
            const roundTrip = verify.exists ? ((verify.data() || {}).testData || null) : null;
            if (roundTrip !== toSave) {
                return res.status(500).json({ ok: false, error: 'Verification failed: stored value did not match' });
            }
            return res.json({ ok: true, testData: roundTrip });
        } catch (e) {
            return res.status(500).json({ ok: false, error: String(e && (e.stack || e.message || e)) });
        }
    });

    app.post('/analytics/report-settings', requireLogin, csrfProtection, async (req, res) => {
        try {
            const { enabled, frequency, email } = req.body || {};
            const ref = db.collection('businesses').doc(req.session.user.uid);
            await ref.set({ reportSettings: { enabled: !!enabled, frequency: frequency || 'weekly', email: email || null, updatedAt: new Date().toISOString() } }, { merge: true });
            res.redirect('/dashboard');
        } catch (e) { console.error('report-settings', e); res.status(500).send('server'); }
    });

    app.post('/team/invite', requireLogin, csrfProtection, async (req, res) => {
        try {
            const { email } = req.body || {};
            if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).send('invalid_email');
            const ref = db.collection('businesses').doc(req.session.user.uid).collection('invites').doc();
            await ref.set({ email, status: 'pending', invitedAt: new Date().toISOString() });
            res.redirect('/dashboard');
        } catch (e) { console.error('team invite', e); res.status(500).send('server'); }
    });
    app.post('/create-checkout-session', requireLogin, csrfProtection, async (req, res) => {
        try {
            if (!process.env.STRIPE_PRICE_ID) {
                const msg = encodeURIComponent('Stripe price is not configured.');
                return res.redirect('/dashboard?e=' + msg);
            }
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const snap = await ref.get();
            const b = snap.data() || {};
            let customerId = b.stripeCustomerId || null;
            if (!customerId) {
                const customer = await stripe.customers.create({
                    email: b.email || req.session.user.email,
                    name: b.businessName || req.session.user.displayName || undefined,
                });
                customerId = customer.id;
                await ref.update({ stripeCustomerId: customerId });
            }
            const sessionObj = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                customer: customerId,
                line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
                mode: 'subscription',
                success_url: `${appUrl}/payment-success`,
                cancel_url: `${appUrl}/dashboard`,
                client_reference_id: req.session.user.uid,
                metadata: { appUserId: req.session.user.uid }
            });
            // Respond JSON for Stripe.js (AJAX), otherwise redirect for normal form POST
            const isAjax = req.xhr || (req.headers['x-requested-with'] === 'XMLHttpRequest') || (req.headers.accept && req.headers.accept.includes('application/json'));
            if (isAjax) {
                return res.json({ id: sessionObj.id, url: sessionObj.url });
            }
            return res.redirect(303, sessionObj.url);
        } catch (error) {
            console.error('❌ Error creating checkout session:', error);
            const msg = encodeURIComponent('Error creating checkout session.');
            return res.redirect('/dashboard?e=' + msg);
        }
    });

    // Start free trial (no charge). Records trial dates and ensures Stripe customer exists for later upgrade
    app.post('/start-free-trial', requireLogin, csrfProtection, async (req, res) => {
        try {
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const snap = await ref.get();
            if (!snap.exists) return res.redirect('/dashboard');
            const data = snap.data() || {};
            // If already pro, nothing to do
            if (data.subscriptionStatus === 'active') return res.redirect('/dashboard');

            // Ensure Stripe customer exists so upgrade is instant later
            let customerId = data.stripeCustomerId || null;
            if (!customerId && process.env.STRIPE_SECRET_KEY) {
                try {
                    const customer = await stripe.customers.create({
                        email: data.email || req.session.user.email,
                        name: data.businessName || req.session.user.displayName || undefined,
                    });
                    customerId = customer.id;
                } catch (stripeErr) {
                    console.warn('Stripe customer create failed; proceeding with app-side trial only');
                }
            }

            const now = new Date();
            const ends = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
            await ref.update({
                stripeCustomerId: customerId,
                subscriptionStatus: 'trial',
                trialStart: now.toISOString(),
                trialEndsAt: ends.toISOString(),
            });
                try {
                    const b = (await ref.get()).data() || {};
                    if (b.email) {
                        await sendEmail({
                            to: b.email,
                            template: 'Free Trial Started Confirmation',
                            data: { businessName: b.businessName || '', trialEndsAt: ends.toISOString(), loginUrl: `${(process.env.APP_BASE_URL||'')}/dashboard` }
                        });
                    }
                } catch (e) { console.warn('postmark trial started failed', e?.message || e); }
            return res.redirect('/dashboard?trial=1');
        } catch (e) {
            console.error('❌ Error starting free trial:', e);
            return res.redirect('/dashboard');
        }
    });
    // Downgrade: cancel at period end (remains active until end)
    app.post('/subscription/cancel', requireLogin, csrfProtection, async (req, res) => {
        try {
            const ref = db.collection('businesses').doc(req.session.user.uid);
            const snap = await ref.get();
            const businessData = snap.data() || {};
            if (!businessData.stripeCustomerId) {
                const isAjax = req.xhr || (req.headers['x-requested-with'] === 'XMLHttpRequest');
                return isAjax ? res.status(400).json({ error: 'missing_customer' }) : res.redirect('/dashboard');
            }
            const subs = await stripe.subscriptions.list({ customer: businessData.stripeCustomerId, status: 'active', limit: 1 });
            if (subs.data && subs.data.length) {
                const sub = subs.data[0];
                await stripe.subscriptions.update(sub.id, { cancel_at_period_end: true });
                await ref.update({ subscriptionStatus: 'active', cancelAtPeriodEnd: true });
            }
            const isAjax = req.xhr || (req.headers['x-requested-with'] === 'XMLHttpRequest');
            return isAjax ? res.json({ ok: true }) : res.redirect('/dashboard');
        } catch (error) {
            console.error('❌ Error canceling subscription:', error);
            const isAjax = req.xhr || (req.headers['x-requested-with'] === 'XMLHttpRequest');
            return isAjax ? res.status(500).json({ error: 'server_error' }) : res.redirect('/dashboard');
        }
    });
    app.get('/payment-success', requireLogin, async (req, res) => {
        try {
            // Status will be updated by Stripe webhook
            console.log(`ℹ️ Checkout completed. Awaiting webhook to activate subscription for user: ${req.session.user.uid}`);
            res.redirect('/dashboard');
        } catch (error) {
            console.error("❌ Error updating subscription status:", error);
            res.status(500).send("Error updating your subscription.");
        }
    });

    // Diagnostics: temporary Postmark test endpoint secured by secret
    app.get('/api/test-email', async (req, res) => {
        try {
            const provided = (req.query && req.query.k) || req.get('x-test-secret') || '';
            const expected = process.env.POSTMARK_TEST_SECRET || '';
            if (!expected || provided !== expected) {
                return res.status(403).send('Forbidden');
            }
            const to = process.env.POSTMARK_TEST_TO || process.env.ADMIN_EMAIL || '';
            if (!to) return res.status(400).send('No test recipient configured');
            console.log('[Diag] Triggering Postmark test email to:', to);
            const result = await sendEmail({
                to,
                template: 'Welcome / Account Creation',
                data: { businessName: 'Integration Test', loginUrl: `${appUrl}/login` }
            });
            try { console.log('[Diag] Postmark send result:', JSON.stringify(result)); } catch(_) { console.log('[Diag] Postmark send result (non-JSON)'); }
            return res.json({ ok: true, result });
        } catch (e) {
            console.error('[Diag] Postmark send error:', e && (e.stack || e.message || e));
            return res.status(500).json({ ok: false, error: e && (e.message || String(e)) });
        }
    });

    // Stripe Billing Portal (POST)
    app.post('/billing-portal', requireLogin, csrfProtection, async (req, res) => {
        try {
            const doc = await db.collection('businesses').doc(req.session.user.uid).get();
            const businessData = doc.data() || {};
            let customerId = businessData.stripeCustomerId;
            if (!customerId) {
                const customer = await stripe.customers.create({ email: businessData.email || req.session.user.email, name: businessData.businessName || req.session.user.displayName || undefined });
                customerId = customer.id;
                await db.collection('businesses').doc(req.session.user.uid).update({ stripeCustomerId: customerId });
            }
            const portalSession = await stripe.billingPortal.sessions.create({
                customer: customerId,
                return_url: `${appUrl}/dashboard`
            });
            res.redirect(303, portalSession.url);
        } catch (error) {
            console.error('❌ Error creating billing portal session:', error);
            res.status(500).send('Error opening billing portal. Please try again later.');
        }
    });

    // Stripe Billing Portal (GET helper to avoid CSRF issues)
    app.get('/billing-portal', requireLogin, async (req, res) => {
        try {
            const doc = await db.collection('businesses').doc(req.session.user.uid).get();
            const businessData = doc.data() || {};
            let customerId = businessData.stripeCustomerId;
            if (!customerId) {
                const customer = await stripe.customers.create({ email: businessData.email || req.session.user.email, name: businessData.businessName || req.session.user.displayName || undefined });
                customerId = customer.id;
                await db.collection('businesses').doc(req.session.user.uid).update({ stripeCustomerId: customerId });
            }
            const portalSession = await stripe.billingPortal.sessions.create({
                customer: customerId,
                return_url: `${appUrl}/dashboard`
            });
            res.redirect(303, portalSession.url);
        } catch (error) {
            console.error('❌ Error creating billing portal session (GET):', error);
            res.status(500).send('Error opening billing portal. Please try again later.');
        }
    });

    // PUBLIC RATING AND FEEDBACK ROUTES
    app.get('/rate/:businessId', csrfProtection, async (req, res) => {
        try {
            const businessId = req.params.businessId;
            const doc = await db.collection('businesses').doc(businessId).get();
            if (!doc.exists) {
                return res.status(404).send("This business is not currently available.");
            }
            const businessData = { ...doc.data(), uid: doc.id };

            // Enrich with Google Places official name
            let placeDisplayName = businessData.businessName || null; // Start with Firestore name as fallback
            try {
                const placeId = businessData.googlePlaceId;
                const apiKey = process.env.GOOGLE_MAPS_API_KEY || null;
                if (placeId && apiKey) {
                    const detailsResp = await fetch(`https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}?fields=displayName`, { headers: { 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': 'displayName' } });
                    if (detailsResp.ok) {
                        const dj = await detailsResp.json();
                        if (dj && dj.displayName && dj.displayName.text) {
                            placeDisplayName = dj.displayName.text;
                        }
                    } else {
                        const errorText = await detailsResp.text().catch(() => `Status: ${detailsResp.status}`);
                        console.warn(`Google Places API error for ${placeId}: ${errorText}`);
                    }
                }
            } catch (e) {
                console.error(`Error fetching Google Place details for ${businessData.googlePlaceId}:`, e);
            }
            // Final fallback if everything else fails
            if (!placeDisplayName) {
                placeDisplayName = (businessData.googlePlaceId ? `Business ID: ${businessData.googlePlaceId.slice(0, 10)}…` : 'A valued business');
            }

            res.render('rate', {
                business: businessData,
                placeDisplayName,
                csrfToken: req.csrfToken(),
                hcaptchaSiteKey: process.env.HCAPTCHA_SITE_KEY || null
            });
        } catch (error) {
            console.error("❌ Error fetching rating page:", error);
            res.status(500).send("Could not load rating page.");
        }
    });

    // Dedicated limiter for feedback submissions
    const feedbackLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

    /* DECOMMISSIONED in favor of /api/v1/reviews
    app.post('/submit-feedback/:businessId', feedbackLimiter, csrfProtection, async (req, res) => {
        try {
            const businessId = req.params.businessId;
            const feedbackData = req.body;

            // Optional: hCaptcha verification
            if (process.env.HCAPTCHA_SECRET && (req.body.hcaptchaToken || req.body['h-captcha-response'])) {
                try {
                    const verifyResp = await fetch('https://hcaptcha.com/siteverify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            secret: process.env.HCAPTCHA_SECRET,
                            response: req.body.hcaptchaToken || req.body['h-captcha-response'],
                            remoteip: req.ip
                        })
                    });
                    const verifyJson = await verifyResp.json();
                    if (!verifyJson.success) return res.status(400).json({ message: 'Captcha failed' });
                } catch (e) {
                    console.error('Captcha verification error:', e);
                    return res.status(400).json({ message: 'Captcha verification error' });
                }
            }

            // Validate payload
            const schema = z.object({
                rating: z.coerce.number().min(1).max(5),
                name: z.string().min(1).max(120),
                email: z.string().email(),
                phone: z.string().max(40).optional().or(z.literal('')),
                feedback: z.string().max(2000).optional(),
                type: z.enum(['positive', 'feedback', 'contact']).optional()
            }).refine((data) => {
                if (data.rating <= 4) {
                    return typeof data.feedback === 'string' && data.feedback.trim().length > 0;
                }
                return true;
            }, { message: 'Feedback required for ratings 4 and below', path: ['feedback'] });

            const parsed = schema.parse(feedbackData);
            await db.collection('businesses').doc(businessId).collection('feedback').add({
                ...parsed,
                createdAt: new Date().toISOString()
            });
            console.log(`✅ Feedback received for business: ${businessId}`);
            res.status(200).json({ message: 'Feedback submitted successfully.' });
        } catch (error) {
            console.error("❌ Error submitting feedback:", error);
            if (error?.issues) {
                return res.status(400).json({ message: 'Invalid input.', details: error.issues });
            }
            res.status(500).json({ message: 'Failed to submit feedback.' });
        }
    });
    */

    // Public unsubscribe handler (?uid=..&c=..&sig=..)
    app.get('/u', async (req, res) => {
        try {
            const uid = String(req.query.uid || '');
            const c = String(req.query.c || '');
            const sig = String(req.query.sig || '');
            if (!uid || !c || !sig) return res.status(400).send('bad_request');
            const contactLower = Buffer.from(c, 'base64url').toString('utf8');
            const payload = `${uid}:${contactLower}`;
            const exp = require('crypto').createHmac('sha256', UNSUBSCRIBE_SECRET).update(payload).digest('base64url');
            if (sig !== exp) return res.status(400).send('invalid');
            const key = Buffer.from(contactLower).toString('base64');
            await db.collection('businesses').doc(uid).collection('optouts').doc(key).set({ at: new Date().toISOString() }, { merge: true });
            return res.status(200).send('You have been unsubscribed.');
        } catch (e) {
            return res.status(500).send('server_error');
        }
    });

    // --- 6. START THE SERVER ---
    // Assets API: secure route to generate QR and PDFs for merchant
    const requireMerchant = (req, res, next) => {
        if (!req.session.user) return res.status(401).json({ error: 'unauthorized' });
        next();
    };

    app.get('/api/merchants/:merchantId/assets', requireMerchant, async (req, res) => {
        try {
            const { merchantId } = req.params;
            if (req.session.user.uid !== merchantId) return res.status(403).json({ error: 'forbidden' });
            const ref = db.collection('businesses').doc(merchantId);
            const snap = await ref.get();
            if (!snap.exists) return res.status(404).json({ error: 'merchant_not_found' });
            const data = snap.data() || {};
            const googlePlaceId = data.googlePlaceId || null;
            const slug = data.shortSlug || (googlePlaceId ? googlePlaceId : 'SETUP');
            const shortLink = `${shortDomain}/${slug}`;
            const needsPlaceId = !data.shortSlug && !googlePlaceId;

            // Prepare output directory
            const outDir = path.join(__dirname, 'public', 'assets', merchantId);
            fs.mkdirSync(outDir, { recursive: true });

            // Generate QR only when link is ready
            let qrPngPath = null;
            let qrSvgPath = null;
            if (!needsPlaceId) {
                qrPngPath = path.join(outDir, 'qr.png');
                qrSvgPath = path.join(outDir, 'qr.svg');
                await QRCode.toFile(qrPngPath, `https://${shortLink}`, { scale: 8, margin: 1 });
                const svgStr = await QRCode.toString(`https://${shortLink}`, { type: 'svg', margin: 1 });
                fs.writeFileSync(qrSvgPath, svgStr, 'utf8');
            }

            // Countertop sign PDF (5x7 inches)
            let signPdfPath = null;
            if (!needsPlaceId && qrPngPath) {
                signPdfPath = path.join(outDir, 'sign.pdf');
                await new Promise((resolve) => {
                    const doc = new PDFDocument({ size: [360, 504] }); // 72 DPI * (5x7)
                    doc.pipe(fs.createWriteStream(signPdfPath)).on('finish', resolve);
                    doc.fontSize(22).text('Leave us a 5‑star review', { align: 'center', margin: 24 });
                    const png = fs.readFileSync(qrPngPath);
                    doc.image(png, (360-200)/2, 120, { width: 200, height: 200 });
                    doc.moveDown(2);
                    doc.fontSize(12).text(shortLink, { align: 'center' });
                    doc.end();
                });
            }

            // Sticker sheet PDF (US Letter with multiple QR codes)
            let stickerPdfPath = null;
            if (!needsPlaceId && qrPngPath) {
                stickerPdfPath = path.join(outDir, 'stickers.pdf');
                await new Promise((resolve) => {
                    const doc = new PDFDocument({ size: 'LETTER', margins: { top: 36, left: 36, right: 36, bottom: 36 } });
                    doc.pipe(fs.createWriteStream(stickerPdfPath)).on('finish', resolve);
                    const png = fs.readFileSync(qrPngPath);
                    const cols = 3, rows = 8; // 24 stickers
                    const cellW = (612 - 72) / cols; // page width - margins
                    const cellH = (792 - 72) / rows; // page height - margins
                    for (let r = 0; r < rows; r++) {
                        for (let c = 0; c < cols; c++) {
                            const x = 36 + c * cellW + (cellW - 120) / 2;
                            const y = 36 + r * cellH + (cellH - 120) / 2;
                            doc.image(png, x, y, { width: 120, height: 120 });
                        }
                    }
                    doc.end();
                });
            }

            const base = `${appUrl}/assets/${merchantId}`;
            return res.json({
                shortLink: shortLink,
                needsPlaceId: needsPlaceId,
                qrCodePngUrl: qrPngPath ? `${base}/qr.png` : null,
                qrCodeSvgUrl: qrSvgPath ? `${base}/qr.svg` : null,
                signPdfUrl: signPdfPath ? `${base}/sign.pdf` : null,
                stickerPdfUrl: stickerPdfPath ? `${base}/stickers.pdf` : null
            });
        } catch (e) {
            console.error('assets api error', e);
            return res.status(500).json({ error: 'server_error' });
        }
    });

    // TEMP: Test Postmark integration endpoint (secured via env key). Remove after diagnostics.
    app.get('/api/test-email', async (req, res) => {
        try {
            const requiredKey = process.env.TEST_EMAIL_KEY || '';
            if (requiredKey && req.query.key !== requiredKey) return res.status(403).json({ error: 'forbidden' });

            const to = process.env.TEST_EMAIL_TO || process.env.ADMIN_EMAIL || '';
            if (!to) return res.status(400).json({ error: 'missing_recipient' });

            const data = { businessName: 'Diagnostics', loginUrl: (process.env.APP_BASE_URL || appUrl || '') + '/login' };
            console.log('▶️ Postmark test: sending to', to);
            const result = await sendEmail({ to, template: 'Welcome / Account Creation', data });
            console.log('✅ Postmark test result:', JSON.stringify(result, null, 2));
            return res.json({ ok: true, result });
        } catch (e) {
            console.error('❌ Postmark test error:', e && (e.stack || e.message || e));
            return res.status(500).json({ error: 'send_failed' });
        }
    });

    app.listen(PORT, HOST, () => {
        console.log(`✅ Server is running and listening on port ${PORT}`);
    });
    
    // --- 6. SHORT LINK RESOLVER (last so it doesn't shadow other routes) ---
    // Handles URLs like https://reviewsandmarketing.com/{slug}
    // Looks up a business by shortSlug or googlePlaceId and redirects to /rate/:businessId
    app.get('/:slug', async (req, res, next) => {
        try {
            const slug = (req.params && req.params.slug) ? String(req.params.slug) : '';
            // Ignore known app paths and static assets
            const reserved = new Set([
                '', 'favicon.ico', 'robots.txt', 'sitemap.xml',
                'login', 'logout', 'signup', 'forgot-password', 'reset-password', 'verify',
                'dashboard', 'pricing', 'features', 'terms', 'privacy', 'healthz',
                'api', 'auth', 'webhooks', 'integrations', 'assets', 'images', 'css', 'js'
            ]);
            if (!slug || reserved.has(slug) || slug.includes('.')) return next();
            // Lookup by shortSlug first
            let businessId = null;
            try {
                const snap1 = await db.collection('businesses').where('shortSlug', '==', slug).limit(1).get();
                if (!snap1.empty) businessId = snap1.docs[0].id;
            } catch (_) {}
            // Fallback: lookup by googlePlaceId
            if (!businessId) {
                try {
                    const snap2 = await db.collection('businesses').where('googlePlaceId', '==', slug).limit(1).get();
                    if (!snap2.empty) businessId = snap2.docs[0].id;
                } catch (_) {}
            }
            if (!businessId) return res.status(404).send('Link not found');
            const dest = `/rate/${businessId}`;
            return res.redirect(302, dest);
        } catch (e) {
            return next();
        }
    });

    // CLEAN ROOM: Standardized Review Submission Endpoint
    app.post('/api/reviews/submit', async (req, res) => {
        // 'targetBusinessId' must be the canonical Auth UID passed from the frontend
        const { rating, comment, targetBusinessId } = req.body;

        console.log(`[CLEANROOM-WRITE] Incoming: UID=${targetBusinessId}, Rating=${rating}`);

        // 1. Strict Validation
        const parsedRating = parseInt(rating, 10);
        if (!targetBusinessId || !parsedRating || parsedRating < 1 || parsedRating > 5) {
            console.error(`[CLEANROOM-WRITE] Validation Failed. Body: ${JSON.stringify(req.body)}`);
            return res.status(400).json({ error: "Invalid submission data." });
        }

        try {
            const newReview = {
                // CRITICAL: Attribution Key (must match owner's Auth UID)
                userId: targetBusinessId,
                rating: parsedRating,
                comment: comment || null,
                // CRITICAL: Server Timestamp for reliable indexing/ordering
                createdAt: FieldValue.serverTimestamp(),
                source: 'cleanroom-v1'
            };

            const docRef = await db.collection('reviews').add(newReview);
            console.log(`[CLEANROOM-WRITE] SUCCESS: Written doc ${docRef.id} for UID: ${targetBusinessId}`);
            res.status(201).json({ success: true });

        } catch (error) {
            console.error("[CLEANROOM-WRITE] ERROR Firestore:", error);
            res.status(500).json({ error: "Server error during submission." });
        }
    });

    // Legacy endpoint for backward compatibility
    app.post('/api/v1/reviews', feedbackLimiter, csrfProtection, async (req, res) => {
        try {
            const { businessId, rating, comment } = req.body;
            console.log(`[LEGACY-WRITE] Incoming: businessId=${businessId} rating=${rating}`);
            
            if (!businessId || !rating) {
                console.error(`[LEGACY-WRITE] ERROR: Missing businessId or rating. Body: ${JSON.stringify(req.body)}`);
                return res.status(400).json({ error: 'Missing businessId or rating' });
            }

            // Forward to clean room endpoint
            req.body = { targetBusinessId: businessId, rating, comment };
            return app._router.handle(req, res, () => {});
        } catch (error) {
            console.error('[LEGACY-WRITE] ERROR:', error);
            res.status(500).json({ error: 'Failed to submit review.' });
        }
    });

    // CLEAN ROOM: Dashboard Pipeline Data API
    app.get('/api/dashboard/pipeline-data', requireLogin, async (req, res) => {
        // CRITICAL: The UID from the authentication middleware
        const loggedInUserId = req.session.user.uid;

        console.log(`[CLEANROOM-READ] Fetching data for UID: ${loggedInUserId}`);
        // Prevent browser caching
        res.setHeader('Cache-Control', 'no-store');

        try {
            // 1. Fetch Insights (Aggregated Stats)
            const businessDocRef = db.collection('businesses').doc(loggedInUserId);
            const businessDoc = await businessDocRef.get();

            if (!businessDoc.exists) {
                console.error(`[CLEANROOM-READ] ERROR: Business document not found for UID: ${loggedInUserId}`);
                return res.status(404).json({ error: "Business profile not found." });
            }

            // Provide default structure if stats object is missing
            const stats = businessDoc.data().stats || {
                 totalFeedback: 0, averageRating: 0.00, fiveStarConversions: 0, histogram: {}
            };

            // 2. Fetch Customer Feedback (Recent Reviews)
            // This query REQUIRES the composite index (userId ASC, createdAt DESC).
            const query = db.collection('reviews')
                .where('userId', '==', loggedInUserId)
                .orderBy('createdAt', 'desc')
                .limit(25); // Fetching the most recent 25 reviews

            const snapshot = await query.get();
            const reviews = snapshot.docs.map(doc => {
                const data = doc.data();
                // Normalize Firestore timestamp for frontend compatibility (ISO String)
                if (data.createdAt && typeof data.createdAt.toDate === 'function') {
                    data.createdAt = data.createdAt.toDate().toISOString();
                }
                return { id: doc.id, ...data };
            });

            console.log(`[CLEANROOM-READ] SUCCESS: Found ${reviews.length} reviews. Stats count: ${stats.totalFeedback}.`);
            res.json({ stats, reviews });

        } catch (error) {
            console.error(`[CLEANROOM-READ] ERROR: ${error.message}`);
            // CRITICAL: Detect indexing failure
            if (error.message.includes('FAILED_PRECONDITION')) {
                console.error("[CLEANROOM-READ] CRITICAL INDEX FAILURE: Composite index (userId ASC, createdAt DESC) is missing or building. Check Firebase Console.");
            }
            res.status(500).json({ error: "Failed to load data.", details: error.message });
        }
    });

    // --- Canonical settings endpoint ---
    app.post('/api/settings', requireLogin, csrfProtection, async (req, res) => {
        try {
            const uid = (req.session && req.session.user && req.session.user.uid) ? req.session.user.uid : null;
            if (!uid) return res.status(401).json({ ok: false, error: 'unauthorized' });

            const ref = db.collection('businesses').doc(uid);
            const payload = req.body || {};
            const updates = {};
            
            // Validate and add googlePlaceId to updates
            if (typeof payload.googlePlaceId === 'string') {
                const cleanId = payload.googlePlaceId.trim();
                if (cleanId.length > 5) { // Basic validation
                    updates.googlePlaceId = cleanId;
                    // Also set shortSlug if it doesn't exist
                    const existingSnap = await ref.get();
                    const existingData = existingSnap.exists ? existingSnap.data() : {};
                    if (!existingData.shortSlug) {
                        updates.shortSlug = cleanId;
                    }
                }
            }

            if (Object.keys(updates).length === 0) {
                return res.status(400).json({ ok: false, error: 'no_valid_settings_provided' });
            }

            updates.updatedAt = new Date().toISOString();

            await ref.set(updates, { merge: true });
            
            // Verify write with detailed logging
            const verifySnap = await ref.get();
            const storedData = verifySnap.exists ? verifySnap.data() : {};
            
            console.log(`[SETTINGS SAVE] uid=${uid}, attempted=${payload.googlePlaceId}, stored=${storedData.googlePlaceId}, docExists=${verifySnap.exists}`);
            
            res.json({ ok: true, settings: storedData, hasGooglePlaceId: !!storedData.googlePlaceId });

        } catch (e) {
            console.error('[/api/settings] error:', e);
            res.status(500).json({ ok: false, error: 'server_error' });
        }
    });

    // Debug endpoint to inspect current user's business document
    app.get('/api/debug/business-doc', requireLogin, async (req, res) => {
        try {
            const uid = req.session.user.uid;
            const ref = db.collection('businesses').doc(uid);
            const snap = await ref.get();
            
            res.json({
                uid,
                exists: snap.exists,
                data: snap.exists ? snap.data() : null,
                hasGooglePlaceId: snap.exists ? !!(snap.data() || {}).googlePlaceId : false
            });
        } catch (e) {
            console.error('[DEBUG] business doc error:', e);
            res.status(500).json({ error: 'server_error' });
        }
    });

    // CRITICAL: Diagnostic endpoint for pipeline analysis (ID trace)
    app.get('/api/admin/debug/pipeline', requireLogin, async (req, res) => {
        try {
            const uid = (req.session && req.session.user && req.session.user.uid) ? req.session.user.uid : null;
            if (!uid) return res.status(401).json({ error: 'unauthorized' });
            
            res.setHeader('Cache-Control', 'no-store');
            console.log(`[DIAGNOSTIC] Starting analysis for UID: ${uid}`);
            
            const diagnostics = { 
                targetUid: uid, 
                results: {}, 
                errors: {},
                timestamp: new Date().toISOString()
            };

            // Strategy 1: Attribution Check (Simple equality filter)
            // If this is empty, the userId used during write does not match targetUid
            try {
                const snap1 = await db.collection('reviews').where('userId', '==', uid).limit(5).get();
                diagnostics.results.attributionCheck = snap1.docs.map(doc => {
                    const data = doc.data();
                    return { 
                        id: doc.id, 
                        userId: data.userId,
                        rating: data.rating,
                        comment: data.comment,
                        createdAt: data.createdAt,
                        businessId: data.businessId
                    };
                });
                console.log(`[DIAGNOSTIC] Attribution check found ${snap1.docs.length} reviews`);
            } catch (error) {
                diagnostics.errors.attributionCheck = error.message;
                console.error('[DIAGNOSTIC] Attribution check error:', error);
            }

            // Strategy 2: Dashboard Query Check (Requires composite index)
            // If Strategy 1 works but this fails/is empty, the index is missing or timestamps are wrong
            try {
                const snap2 = await db.collection('reviews')
                    .where('userId', '==', uid)
                    .orderBy('createdAt', 'desc')
                    .limit(5)
                    .get();
                
                diagnostics.results.dashboardQuery = snap2.docs.map(doc => {
                    const data = doc.data();
                    // Normalize timestamp for frontend
                    if (data.createdAt && typeof data.createdAt.toDate === 'function') {
                        data.createdAt = data.createdAt.toDate().toISOString();
                    }
                    return { 
                        id: doc.id, 
                        userId: data.userId,
                        rating: data.rating,
                        comment: data.comment,
                        createdAt: data.createdAt,
                        businessId: data.businessId
                    };
                });
                console.log(`[DIAGNOSTIC] Dashboard query found ${snap2.docs.length} reviews`);
            } catch (error) {
                diagnostics.errors.dashboardQuery = error.message;
                if (error.message.includes('FAILED_PRECONDITION')) {
                    console.error('[DIAGNOSTIC] FAILED_PRECONDITION: Index is missing or building.');
                }
                console.error('[DIAGNOSTIC] Dashboard query error:', error);
            }

            // Strategy 3: Business Document Check
            try {
                const businessDoc = await db.collection('businesses').doc(uid).get();
                if (businessDoc.exists) {
                    const businessData = businessDoc.data();
                    diagnostics.results.businessDoc = {
                        exists: true,
                        shortSlug: businessData.shortSlug,
                        googlePlaceId: businessData.googlePlaceId,
                        stats: businessData.stats || null
                    };
                } else {
                    diagnostics.results.businessDoc = { exists: false };
                }
            } catch (error) {
                diagnostics.errors.businessDoc = error.message;
            }

            console.log(`[DIAGNOSTIC] Analysis complete for UID: ${uid}`);
            res.status(200).json(diagnostics);

        } catch (error) {
            console.error(`[DIAGNOSTIC] ERROR: ${error.message}`);
            res.status(500).json({ error: 'server_error' });
        }
    });
    })().catch((err) => {
        console.error('❌ Fatal startup error', err);
        process.exit(1);
    });
