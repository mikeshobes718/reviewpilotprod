    // server.js (Production Ready)

    // --- 1. LOAD THE TOOLS ---
    require('dotenv').config();
    const express = require('express');
    const { initializeApp, cert } = require('firebase-admin/app');
    const { getFirestore } = require('firebase-admin/firestore');
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
        const shortDomain = process.env.SHORT_LINK_DOMAIN || 'reviewpilot.link';

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
            const { Queue, Worker, QueueScheduler } = require('bullmq');
            const IORedis = require('ioredis');
            const redisConnection = new IORedis(process.env.REDIS_URL);
            reviewQueue = new Queue('review-requests', { connection: redisConnection });
            new QueueScheduler('review-requests', { connection: redisConnection });
            new Worker('review-requests', async (job) => {
                const { channel, customer, merchantId, shortLink } = job.data || {};
                if (isQuietHours()) {
                    const next8am = new Date();
                    if (next8am.getHours() >= 21) next8am.setDate(next8am.getDate() + 1);
                    next8am.setHours(8,0,0,0);
                    const delay = next8am.getTime() - Date.now();
                    await reviewQueue.add('sendReviewRequest', job.data, { delay, attempts: 1 });
                    return;
                }
                console.log(`Would send ${channel} to ${customer?.email || customer?.phone} → ${shortLink} (merchant ${merchantId})`);
            }, { connection: redisConnection });
        } else {
            console.warn('REDIS_URL not set; review-requests queue disabled');
        }

        function isQuietHours(date = new Date()) {
            // Basic quiet hours 21:00-08:00 in server time
            const hour = date.getHours();
            return (hour >= 21 || hour < 8);
        }

        

        // --- 3c. KMS helpers for encrypting tokens ---
        const { KMSClient, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');
        const kms = new KMSClient({ region: awsRegion });
        const KMS_KEY_ID = process.env.KMS_KEY_ID || undefined; // use default if absent
        async function encryptString(plain) {
            const cmd = new EncryptCommand({ KeyId: KMS_KEY_ID, Plaintext: Buffer.from(plain) });
            const res = await kms.send(cmd);
            return Buffer.from(res.CiphertextBlob).toString('base64');
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
            try { if (req.session && req.session.user && req.session.user.uid) return req.session.user.uid; } catch(_) {}
            try {
                const raw = req.cookies && req.cookies.session;
                if (raw) {
                    const jwt = require('jsonwebtoken');
                    const d = jwt.decode(raw);
                    if (d && d.sub) return d.sub;
                }
            } catch(_) {}
            return null;
        }

        // --- Auth guards (define before routes use them) ---
        const requireLogin = (req, res, next) => {
            try {
                if (!(req.session && req.session.user)) {
                    const raw = req.cookies && req.cookies.session;
                    if (raw) {
                        try { const jwt = require('jsonwebtoken'); const decoded = jwt.decode(raw); if (decoded && decoded.sub) { req.session.user = { uid: decoded.sub, email: null, displayName: null }; } } catch(_) {}
                    }
                }
            } catch(_) {}
            if (req.session && req.session.user) return next();
            try { console.warn('requireLogin redirect: no session.user; cookies:', Object.keys(req.cookies||{})); } catch(_) {}
            return res.redirect(302, '/login');
        };
        const requireAccess = async (req, res, next) => {
            try {
                if (!req.session || !req.session.user) return res.redirect(302, '/login');
                let status = null;
                let trialEndsAt = null;
                try {
                    const doc = await db.collection('businesses').doc(req.session.user.uid).get();
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
                if (!hasAccess) return res.redirect(302, '/pricing');
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
                // For server flow, redirect back to dashboard
                res.redirect('/dashboard');
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
                res.redirect('/dashboard');
            } catch (e) {
                console.error('square callback error (alias)', e);
                res.status(500).send('server_error');
            }
        });

        // Connection status for UI single source of truth
        app.get('/api/pos/connection-status', requireLogin, async (req, res) => {
            try {
                const doc = await db.collection('businesses').doc(req.session.user.uid).get();
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
                        await reviewQueue.add('sendReviewRequest', { channel: settings.channel || 'email', customer, merchantId: merchantId || '', shortLink }, { delay: delayMs, attempts: 1 });
                    } else {
                        console.log('Queue not configured; skipping enqueue');
                    }
                }
                res.status(200).send('ok');
            } catch (e) { console.error('square webhook error', e); res.status(200).send('ok'); }
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
    app.use(cookieParser());
    app.use(session({
        secret: process.env.SESSION_SECRET || 'a-super-secret-key-that-you-should-change',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            sameSite: 'lax',
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
                        return parts.join('; ');
                    };
                    const val = sanitize(rawSetCookie);
                    res.setHeader('Set-Cookie', val);
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
                        return req.session.save((err) => { if (err) console.warn('session save error (auth bridge):', err); return res.redirect('/dashboard'); });
                    }
                } catch (_) { /* ignore bridge errors */ }
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
    app.get('/dashboard', requireAccess, (req, res, next) => { next(); });
    // Verify email (custom auth) - GET handler to consume token & email
    app.get('/verify', csrfProtection, async (req, res) => {
        try {
            const tokenPlain = (req.query && req.query.token) || '';
            const email = (req.query && req.query.email) || '';
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
            if (!tokenPlain || !email) return res.status(400).render('verify', { csrfToken: req.csrfToken(), email, error: 'Invalid link.', user: req.session.user || null });
            // Forward to API
            const base = process.env.API_GATEWAY_BASE_URL || process.env.AUTH_API_BASE || '';
            const url = (base || 'https://becb9v5qw8.execute-api.us-east-1.amazonaws.com/prod') + '/verify-email';
            const r = await fetch(url, { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ token: tokenPlain, email }) });
            if (r.ok) return res.redirect('/login?verified=1');
            return res.status(400).render('verify', { csrfToken: req.csrfToken(), email, error: 'Verification failed. Request a new link from Login → Forgot password.', user: req.session.user || null });
        } catch (e) {
            return res.status(500).render('verify', { csrfToken: req.csrfToken(), email: (req.query && req.query.email) || '', error: 'Server error. Try again.', user: req.session.user || null });
        }
    });
    app.post('/signup', async (req, res) => {
        try {
            const { businessName, email, password } = req.body || {};
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            const clean = (v) => (typeof v === 'string' ? v.trim() : '');
            const nameClean = clean(businessName);
            const passClean = clean(password);
            const emailRaw = clean(email);
            let decodedEmail = emailRaw;
            try { decodedEmail = decodeURIComponent(emailRaw); } catch (_) { /* ignore */ }
            decodedEmail = decodedEmail.replace(/\s+/g, '');

            if (!nameClean || !decodedEmail || !passClean) {
                return res.status(400).render('signup', { csrfToken: token, error: 'Missing fields' });
            }

            // If this is an AJAX request, prefer JSON responses
            const isAjax = req.xhr || (req.headers['x-requested-with'] === 'XMLHttpRequest') || (req.headers.accept && req.headers.accept.includes('application/json'));

            // Duplicate email pre-check in our database
            try {
                const existingSnap = await db.collection('businesses').where('email', '==', decodedEmail).limit(1).get();
                if (!existingSnap.empty) {
                    if (isAjax) {
                        return res.status(409).json({ error: 'EMAIL_ALREADY_REGISTERED' });
                    } else {
                        return res.status(409).render('signup', { csrfToken: token, error: 'An account with this email already exists. Please <a href="/login">log in</a> instead.' });
                    }
                }
            } catch (_) { /* non-fatal: continue to signup */ }

            const signUpRes = await cognito.send(new SignUpCommand({
                ClientId: COGNITO_CLIENT_ID,
                Username: decodedEmail,
                Password: passClean,
                UserAttributes: [
                    { Name: 'email', Value: decodedEmail },
                    { Name: 'name', Value: nameClean }
                ]
            }));
            const userSub = signUpRes?.UserSub;

            const customer = await stripe.customers.create({ email: decodedEmail, name: nameClean });

            if (userSub) {
                await db.collection('businesses').doc(userSub).set({
                    businessName: nameClean,
                    email: decodedEmail,
                    googlePlaceId: null,
                    stripeCustomerId: customer.id,
                    subscriptionStatus: 'incomplete',
                createdAt: new Date().toISOString(),
            });
                const base = (nameClean || 'merchant').replace(/[^A-Za-z0-9]/g, '').slice(0,6).toUpperCase();
                const rand = Math.random().toString(36).slice(2,5).toUpperCase();
                await db.collection('businesses').doc(userSub).set({ shortSlug: `${base}${rand}` }, { merge: true });
                // Non-fatal email send
                try {
                    const verificationUrl = `${(process.env.APP_BASE_URL || '')}/confirm?email=${encodeURIComponent(decodedEmail)}`;
                    await sendEmail({ to: decodedEmail, template: 'Email Address Verification', data: { businessName: nameClean, verificationUrl } });
                } catch (_) { /* ignore email errors */ }
            }

            if (isAjax) {
                return res.json({ redirect: `/verify?email=${encodeURIComponent(decodedEmail)}` });
            }
            return res.redirect(`/verify?email=${encodeURIComponent(decodedEmail)}`);
        } catch (error) {
            console.error('Signup error:', error && (error.message || error));
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            let userMsg = 'Signup failed. Try a different email.';
            let passwordMsg = null;
            const errName = (error && (error.name || error.code)) || '';
            const errText = (error && (error.message || '')) || '';
            const isAjax = req.xhr || (req.headers['x-requested-with'] === 'XMLHttpRequest') || (req.headers.accept && req.headers.accept.includes('application/json'));
            if (errName === 'UsernameExistsException') {
                if (isAjax) {
                    return res.status(409).json({ error: 'EMAIL_ALREADY_REGISTERED' });
                }
                return res.status(409).render('signup', { csrfToken: token, error: 'An account with this email already exists. Please <a href="/login">log in</a> instead.' });
            }
            if (errName === 'InvalidPasswordException' || /Password.*symbol|Password.*requirements|conform with policy|complex/i.test(errText)) {
                passwordMsg = 'Password must include at least one symbol (!@#$%).';
                userMsg = null;
            }
            if (isAjax) {
                return res.status(400).json({ error: userMsg ? 'GENERIC_SIGNUP_FAILED' : 'PASSWORD_POLICY', message: userMsg || passwordMsg || 'Signup failed' });
            }
            return res.status(400).render('signup', { csrfToken: token, error: userMsg, passwordError: passwordMsg });
        }
    });

    // New confirmation landing route (legacy alias)
    app.get('/confirm', (req, res) => {
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        const email = (req.query && req.query.email) || '';
        return res.render('verify', { csrfToken: token, email, user: req.session.user || null });
    });

    // (legacy explicit verify page removed)

    // Verify email endpoint (confirm signup with code)
    app.post('/verify-email', csrfProtection, async (req, res) => {
        try {
            const { email, verificationCode } = req.body || {};
            if (!email || !verificationCode) {
                return res.status(400).json({ error: 'MISSING_FIELDS' });
            }
            try {
                await cognito.send(new ConfirmSignUpCommand({
                    ClientId: COGNITO_CLIENT_ID,
                    Username: email,
                    ConfirmationCode: String(verificationCode).trim()
                }));
            } catch (err) {
                const name = (err && (err.name || err.code)) || '';
                let errorCode = 'VERIFY_FAILED';
                if (name === 'CodeMismatchException') errorCode = 'CODE_MISMATCH';
                else if (name === 'ExpiredCodeException') errorCode = 'CODE_EXPIRED';
                else if (name === 'UserNotFoundException') errorCode = 'USER_NOT_FOUND';
                else if (name === 'NotAuthorizedException') errorCode = 'ALREADY_CONFIRMED';
                console.error('verify-email error:', err);
                return res.status(400).json({ error: errorCode, message: err && err.message ? err.message : 'Verification failed' });
            }
            return res.json({ ok: true });
        } catch (e) {
            console.error('verify-email server error:', e);
            return res.status(500).json({ error: 'SERVER_ERROR' });
        }
    });

    // Legacy path retained for compatibility
    app.get('/verify-email', (req, res) => {
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        const email = req.query && req.query.email ? req.query.email : '';
        res.render('confirm', { csrfToken: token, email, user: req.session.user || null });
    });
    // (superseded above)
    app.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body || {};
            if (!email || !password) return res.status(400).render('login', { csrfToken: req.csrfToken(), error: 'Missing email or password.' });
            let authRes = await cognito.send(new InitiateAuthCommand({
                AuthFlow: 'USER_PASSWORD_AUTH',
                ClientId: COGNITO_CLIENT_ID,
                AuthParameters: { USERNAME: email, PASSWORD: password }
            }));
            // Handle NEW_PASSWORD_REQUIRED challenge
            if (authRes && authRes.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
                req.session.cognitoNewPassword = { session: authRes.Session, username: email };
                return res.redirect('/new-password');
            }
            const accessToken = authRes?.AuthenticationResult?.AccessToken;
            if (!accessToken) throw new Error('Invalid login');
            const me = await cognito.send(new GetUserCommand({ AccessToken: accessToken }));
            const sub = me?.Username;
            const attrs = Object.fromEntries((me?.UserAttributes || []).map(a => [a.Name, a.Value]));
            if (attrs && String(attrs.email_verified) !== 'true') {
                // Enforce verification: block login until verified
                return res.redirect(`/verify?email=${encodeURIComponent(attrs.email || email)}`);
            }

            // On first Cognito login, if this merchant previously existed (Firebase UID),
            // clone their business doc by matching email so they keep their data.
            try {
                const hasDoc = await db.collection('businesses').doc(sub).get();
                if (!hasDoc.exists && attrs.email) {
                    const legacy = await db.collection('businesses').where('email', '==', attrs.email).limit(1).get();
                    if (!legacy.empty) {
                        await db.collection('businesses').doc(sub).set(legacy.docs[0].data());
                    }
                }
            } catch (_) { /* non-fatal */ }
            req.session.user = { uid: sub, email: attrs.email || email, displayName: attrs.name || null };
            console.log(`✅ Cognito login session created for: ${email}`);
            // Send Welcome email on first verified login (once)
            try {
                const ref = db.collection('businesses').doc(sub);
                const doc = await ref.get();
                const b = doc.exists ? doc.data() : {};
                if (!b || !b.welcomeSent) {
                    await sendEmail({
                        to: attrs.email || email,
                        template: 'Welcome / Account Creation',
                        data: { businessName: attrs.name || '', loginUrl: `${(process.env.APP_BASE_URL||'')}/dashboard` }
                    });
                    await ref.set({ welcomeSent: true }, { merge: true });
                }
            } catch (e) { console.warn('postmark welcome send failed', e?.message || e); }
            // Optional: New device login alert (basic heuristic: check user-agent hash vs last)
            try {
                const ua = (req.headers['user-agent'] || '').slice(0,200);
                const uaHash = require('crypto').createHash('sha256').update(ua).digest('hex');
                const ref = db.collection('businesses').doc(sub);
                const snap = await ref.get();
                const prev = snap.exists ? (snap.data().lastUaHash || null) : null;
                if (uaHash && uaHash !== prev) {
                    await sendEmail({
                        to: attrs.email || email,
                        template: 'New Device Login Alert',
                        data: {
                            businessName: attrs.name || '',
                            loginTime: new Date().toISOString(),
                            loginLocation: 'Unknown',
                            loginDevice: ua || 'Unknown',
                            resetUrl: `${(process.env.APP_BASE_URL || '')}/reset-password`
                        }
                    });
                    await ref.set({ lastUaHash: uaHash }, { merge: true });
                }
            } catch (e) { console.warn('postmark device alert failed', e?.message || e); }
            return req.session.save((err) => {
                if (err) console.warn('session save error (login):', err);
            return res.redirect('/dashboard');
            });
        } catch (error) {
            const errMsg = (error && (error.name || error.code || error.message)) || '';
            console.error('❌ Cognito login error:', errMsg);
            if (['NotAuthorizedException','UserNotFoundException','UserNotConfirmedException','InvalidParameterException'].includes(errMsg)) {
                try {
                    const { email } = req.body || {};
                    const snap = await db.collection('businesses').where('email', '==', email).limit(1).get();
                    if (!snap.empty) {
                        try {
                            await cognito.send(new AdminCreateUserCommand({ UserPoolId: COGNITO_USER_POOL_ID, Username: email, UserAttributes: [{ Name: 'email', Value: email }, { Name: 'email_verified', Value: 'true' }, { Name: 'name', Value: snap.docs[0].data().businessName || '' }] }));
                        } catch(_){}
                        try { await cognito.send(new AdminSetUserPasswordCommand({ UserPoolId: COGNITO_USER_POOL_ID, Username: email, Password: (req.body && req.body.password) || '', Permanent: true })); } catch(_){ }
                        try { await cognito.send(new AdminConfirmSignUpCommand({ UserPoolId: COGNITO_USER_POOL_ID, Username: email })); } catch(_){ }
                        // Retry auth
                        const authRes = await cognito.send(new InitiateAuthCommand({
                            AuthFlow: 'USER_PASSWORD_AUTH',
                            ClientId: COGNITO_CLIENT_ID,
                            AuthParameters: { USERNAME: email, PASSWORD: (req.body && req.body.password) || '' }
                        }));
                        if (authRes && authRes.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
                            req.session.cognitoNewPassword = { session: authRes.Session, username: email };
                            return res.redirect('/new-password');
                        }
                        const accessToken2 = authRes?.AuthenticationResult?.AccessToken;
                        if (accessToken2) {
                            const me = await cognito.send(new GetUserCommand({ AccessToken: accessToken2 }));
                            const sub = me?.Username; const attrs = Object.fromEntries((me?.UserAttributes || []).map(a => [a.Name, a.Value]));
                            if (attrs && String(attrs.email_verified) !== 'true') {
                                return res.redirect(`/verify?email=${encodeURIComponent(attrs.email || email)}`);
                            }
                            req.session.user = { uid: sub, email: attrs.email || email, displayName: attrs.name || null };
                            return req.session.save((err) => {
                                if (err) console.warn('session save error (fallback login):', err);
                                return res.redirect('/dashboard');
                            });
                        }
                    }
                } catch (e2) { console.warn('auto-signup fallback failed', e2?.message || e2); }
            }
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            let userMsg = 'Invalid email or password.';
            let resendLink = null;
            let showHint = true;
            if (/Password.*requirements|Password.*minimum|Password.*complex/i.test(errMsg)) {
                userMsg = 'Password does not meet complexity requirements.';
            }
            if (/UserNotConfirmed/i.test(errMsg)) {
                userMsg = 'Your account is not confirmed. Please check your email for a verification link.';
                const { email } = req.body || {};
                if (email) resendLink = `/resend-confirmation?email=${encodeURIComponent(email)}`;
                showHint = false;
            }
            if (/NotAuthorizedException/i.test(errMsg)) {
                userMsg = 'Incorrect email or password.';
            }
            return res.status(200).render('login', { csrfToken: token, error: userMsg, hint: showHint ? errMsg : null, resendLink });
        }
    });

    // Removed Firebase token session endpoint; server handles Cognito login
    app.get('/logout', (req, res) => {
        req.session.destroy(() => res.redirect('/login'));
    });

    // Password reset
    app.get('/reset-password', csrfProtection, (req, res) => {
        res.render('reset', { csrfToken: req.csrfToken(), sent: false, error: null, user: req.session.user || null });
    });
    app.post('/reset-password', csrfProtection, async (req, res) => {
        try {
            const { email } = req.body || {};
            // Prefer branded email: generate password reset link with continue URL to our handler
            try {
                await cognito.send(new ForgotPasswordCommand({ ClientId: COGNITO_CLIENT_ID, Username: email }));
            } catch (error) {
                try { console.error('CRITICAL FORGOT_PASSWORD ERROR:', error); } catch(_) { console.error('CRITICAL FORGOT_PASSWORD ERROR (string):', String(error)); }
                throw error;
            }
            try {
                await sendEmail({
                    to: email,
                    template: 'Password Reset Request',
                    data: { businessName: '', resetUrl: `${(process.env.APP_BASE_URL || '')}/reset-password` }
                });
            } catch (e) { console.warn('postmark reset send failed', e?.message || e); }
            return res.render('reset', { csrfToken: req.csrfToken(), sent: true, error: null, email });
        } catch (e) {
            console.error('Reset exception:', e);
            return res.status(500).render('reset', { csrfToken: req.csrfToken(), sent: false, error: 'Unexpected error. Try again.' });
        }
    });

    // Link-based password update page (inside app lifecycle)
    app.get('/update-password', csrfProtection, (req, res) => {
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        const email = (req.query && req.query.email) || '';
        const code = (req.query && req.query.code) || '';
        return res.render('update-password', { csrfToken: token, email, code, error: null, user: req.session.user || null });
    });
    app.post('/update-password', csrfProtection, async (req, res) => {
        try {
            const { email, code, newPassword, confirmPassword } = req.body || {};
            if (!email || !code || !newPassword || newPassword !== confirmPassword) {
                return res.status(400).render('update-password', { csrfToken: req.csrfToken(), email, code, error: 'Please enter matching passwords.' });
            }
            try {
                await cognito.send(new ConfirmForgotPasswordCommand({ ClientId: COGNITO_CLIENT_ID, Username: email, ConfirmationCode: code, Password: newPassword }));
            } catch (error) {
                console.error('CRITICAL CONFIRM_FORGOT_PASSWORD ERROR:', error);
                return res.status(400).render('update-password', { csrfToken: req.csrfToken(), email, code, error: 'Could not update password. Check your link and try again.' });
            }
            return res.redirect('/login');
        } catch (e) {
            console.error('update-password server error:', e);
            return res.status(500).render('update-password', { csrfToken: req.csrfToken(), email: (req.body && req.body.email) || '', code: (req.body && req.body.code) || '', error: 'Unexpected error. Try again.' });
        }
    });

    // Firebase Action handler (password reset)
    app.get('/auth/action', csrfProtection, async (req, res) => {
        try {
            const { mode, oobCode } = req.query || {};
            if (mode !== 'resetPassword' || !oobCode) {
                return res.status(400).send('Invalid action');
            }
            const apiKey = process.env.FIREBASE_API_KEY;
            // Verify code to get email
            const v = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=${apiKey}`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ oobCode })
            });
            const vjson = await v.json();
            if (!v.ok || !vjson.email) {
                return res.status(400).send('This password reset link is invalid or expired.');
            }
            return res.render('action', { csrfToken: req.csrfToken(), oobCode, email: vjson.email });
        } catch (e) { console.error('action get error', e); return res.status(500).send('Server error'); }
    });
    app.post('/auth/action', csrfProtection, async (req, res) => {
        try {
            const apiKey = process.env.FIREBASE_API_KEY;
            const { oobCode, newPassword } = req.body || {};
            if (!oobCode || !newPassword) return res.status(400).send('Missing fields');
            const c = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=${apiKey}`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ oobCode, newPassword })
            });
            const cjson = await c.json().catch(()=>({}));
            if (!c.ok) {
                const msg = (cjson && cjson.error && cjson.error.message) || 'Could not reset password.';
                return res.status(400).render('action', { csrfToken: req.csrfToken(), oobCode, email: '', error: msg });
            }
            try {
                // Send confirmation email
                const email = cjson && cjson.email ? cjson.email : '';
                await sendEmail({
                    to: email,
                    template: 'Password Changed Confirmation',
                    data: { businessName: '', loginUrl: `${(process.env.APP_BASE_URL||'')}/login`, changedAt: new Date().toISOString() }
                });
            } catch (e) { console.warn('postmark password changed failed', e?.message || e); }
            return res.redirect('/login');
        } catch (e) { console.error('action post error', e); return res.status(500).send('Server error'); }
    });

    // DASHBOARD & SETTINGS ROUTES
    app.get('/dashboard', requireAccess, csrfProtection, async (req, res) => {
        try {
            const businessDoc = await db.collection('businesses').doc(req.session.user.uid).get();
            if (!businessDoc.exists) throw new Error('No business data found.');
            const feedbackSnapshot = await db.collection('businesses').doc(req.session.user.uid).collection('feedback').orderBy('createdAt', 'desc').get();
            const feedback = feedbackSnapshot.docs.map(doc => doc.data());

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
            res.render('dashboard', {
                business: businessDoc.data(),
                user: req.session.user,
                feedback: feedback,
                appUrl: appUrl, // Pass the appUrl to the dashboard
                csrfToken: req.csrfToken(),
                analytics: { total, avg, counts, conversions },
                billing,
                pageError: req.query && req.query.e ? decodeURIComponent(req.query.e) : null
            });
        } catch (error) {
            console.error("❌ Error fetching dashboard data (temporary fallback shown):", error);
            // Render dashboard shell with placeholders while Firestore index builds
            try {
                const placeholderAnalytics = { total: 0, avg: '0.00', counts: { 1:0, 2:0, 3:0, 4:0, 5:0 }, conversions: 0 };
                return res.render('dashboard', {
                    business: { businessName: '', email: (req.session.user && req.session.user.email) || '', subscriptionStatus: 'none' },
                    user: req.session.user,
                    feedback: [],
                    appUrl: appUrl,
                    csrfToken: req.csrfToken(),
                    analytics: placeholderAnalytics,
                    billing: null,
                    pageError: 'Loading data…'
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

    app.post('/admin/refund', express.urlencoded({extended:true}), async (req, res) => {
        try {
            if (!req.session.user || req.session.user.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
            const { chargeId } = req.body || {};
            if (!chargeId) return res.status(400).send('Missing chargeId');
            const refund = await stripe.refunds.create({ charge: chargeId });
            res.json({ ok: true, refund });
        } catch (e) { console.error('Refund error', e); res.status(500).json({ ok:false }); }
    });

    app.post('/update-settings', requireLogin, csrfProtection, async (req, res) => {
        try {
            const { googlePlaceId } = req.body;
            await db.collection('businesses').doc(req.session.user.uid).update({
                googlePlaceId: googlePlaceId
            });
            console.log(`✅ Settings updated for user: ${req.session.user.uid}`);
            res.redirect('/dashboard');
        } catch (error) {
            console.error("❌ Error updating settings:", error);
            res.status(500).send("Error updating settings.");
        }
    });

    // PAYMENT ROUTES
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
            if (!doc.exists || doc.data().subscriptionStatus !== 'active') {
                return res.status(404).send("This business is not currently active.");
            }
            const businessData = { ...doc.data(), uid: doc.id };
            res.render('rate', { business: businessData, csrfToken: req.csrfToken(), hcaptchaSiteKey: process.env.HCAPTCHA_SITE_KEY || null });
        } catch (error) {
            console.error("❌ Error fetching rating page:", error);
            res.status(500).send("Could not load rating page.");
        }
    });

    // Dedicated limiter for feedback submissions
    const feedbackLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

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
    })().catch((err) => {
        console.error('❌ Fatal startup error', err);
        process.exit(1);
    });
