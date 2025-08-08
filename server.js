    // server.js (Production Ready)

    // --- 1. LOAD THE TOOLS ---
    require('dotenv').config();
    const express = require('express');
    const { initializeApp, cert } = require('firebase-admin/app');
    const { getFirestore } = require('firebase-admin/firestore');
    const { getAuth } = require('firebase-admin/auth');
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const session = require('express-session');
    const cookieParser = require('cookie-parser');
    const helmet = require('helmet');
    const compression = require('compression');
    const rateLimit = require('express-rate-limit');
    const csurf = require('csurf');
    const morgan = require('morgan');
    const { z } = require('zod');

    // --- 2. INITIALIZE THE APP ---
    const app = express();
    const PORT = process.env.PORT || 3000;
    const HOST = '0.0.0.0'; // Necessary for some hosting platforms
    const isProduction = process.env.NODE_ENV === 'production';

    // --- 3. FIREBASE SETUP ---
    // Heroku uses an environment variable for the service account, while local uses a file.
    const serviceAccount = process.env.GOOGLE_CREDENTIALS ?
      JSON.parse(process.env.GOOGLE_CREDENTIALS) :
      require('./serviceAccountKey.json');

    initializeApp({
      credential: cert(serviceAccount),
      projectId: 'review-saas-prod',
    });
    const db = getFirestore();
    const auth = getAuth();

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
                        'https://cdnjs.cloudflare.com'
                    ],
                    imgSrc: ["'self'", 'data:', 'https:'],
                    styleSrc: ["'self'", "'unsafe-inline'", 'https:'],
                    fontSrc: ["'self'", 'https:', 'data:'],
                    frameSrc: ["'self'", 'https://www.youtube.com', 'https://www.youtube-nocookie.com'],
                    connectSrc: [
                        "'self'",
                        'https://plausible.io',
                        'https://www.google-analytics.com',
                        'https://identitytoolkit.googleapis.com'
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
                    // Find business by stripeCustomerId
                    const snap = await db.collection('businesses').where('stripeCustomerId', '==', customerId).limit(1).get();
                    if (!snap.empty) {
                        const docRef = snap.docs[0].ref;
                        await docRef.update({ subscriptionStatus: 'active' });
                        console.log('✅ Subscription activated via webhook for customer:', customerId);
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

    // CSRF protection (opt-in per route)
    const csrfProtection = csurf();
    // Friendly CSRF error handler
    app.use((err, req, res, next) => {
        if (err && err.code === 'EBADCSRFTOKEN') {
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            if (req.path.startsWith('/login')) {
                return res.status(403).render('login', { csrfToken: token, error: 'Security check failed. Please try again.' });
            }
            if (req.path.startsWith('/signup')) {
                return res.status(403).render('signup', { csrfToken: token, error: 'Security check failed. Please try again.' });
            }
            return res.status(403).send('Form expired. Refresh and try again.');
        }
        next(err);
    });

    const requireLogin = (req, res, next) => {
        if (req.session.user) {
            next();
        } else {
            res.redirect('/login');
        }
    };

    // --- 5. DEFINE THE ROUTES (THE "URLS") ---
    // Preferred explicit base URL for links shown in the UI (dashboard public link, success/cancel URLs)
    // In production set APP_BASE_URL (e.g. https://your-app.herokuapp.com). Fallbacks are provided.
    const appUrl = process.env.APP_BASE_URL
        || (process.env.HEROKU_APP_NAME ? `https://${process.env.HEROKU_APP_NAME}.herokuapp.com` : null)
        || (isProduction ? `http://localhost:${PORT}` : `http://lvh.me:${PORT}`);

    // AUTH ROUTES
    app.get('/healthz', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'development' }));
    app.get('/', csrfProtection, (req, res) => res.render('index', { csrfToken: req.csrfToken(), title: 'ReviewPilot • Turn happy customers into 5‑star reviews', user: req.session.user || null }));
    app.get('/features', csrfProtection, (req, res) => res.render('features', { csrfToken: req.csrfToken(), title: 'Features • ReviewPilot', user: req.session.user || null }));
    app.get('/pricing', csrfProtection, (req, res) => res.render('pricing', { csrfToken: req.csrfToken(), title: 'Pricing • ReviewPilot', user: req.session.user || null }));
    app.get('/privacy', csrfProtection, (req, res) => res.render('privacy', { csrfToken: req.csrfToken(), title: 'Privacy Policy • ReviewPilot', user: req.session.user || null }));
    app.get('/signup', (req, res) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        res.render('signup', { csrfToken: token, error: null, user: req.session.user || null });
    });
    app.post('/signup', async (req, res) => {
        try {
            const { businessName, email, password } = req.body;
            const userRecord = await auth.createUser({ email, password, displayName: businessName });
            const customer = await stripe.customers.create({ email, name: businessName });
            await db.collection('businesses').doc(userRecord.uid).set({
                businessName, email, googlePlaceId: null,
                stripeCustomerId: customer.id, subscriptionStatus: 'incomplete',
                createdAt: new Date().toISOString(),
            });
            console.log(`✅ Full signup complete for: ${email}`);
            res.redirect('/login');
        } catch (error) {
            console.error("❌ Error during signup:", error);
            let msg = 'Something went wrong during signup.';
            if (error?.errorInfo?.code === 'auth/email-already-exists') {
                msg = 'That email is already in use. Try logging in or use a different email.';
            }
            const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
            res.status(400).render('signup', { csrfToken: token, error: msg });
        }
    });
    app.get('/login', (req, res) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        const error = req.query.e ? decodeURIComponent(req.query.e) : (req.session.__flashError || null);
        req.session.__flashError = null;
        const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
        res.render('login', { csrfToken: token, error, firebaseApiKey: process.env.FIREBASE_API_KEY || '', user: req.session.user || null });
    });
    app.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body;
            // Verify credentials using Firebase Identity Toolkit
            const apiKey = process.env.FIREBASE_API_KEY;
            if (!apiKey) {
                const token = typeof req.csrfToken === 'function' ? req.csrfToken() : '';
                return res.status(200).render('login', { csrfToken: token, error: 'Login temporarily unavailable (missing API key).', firebaseApiKey: '' });
            }
            const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, returnSecureToken: true })
            });
            if (!resp.ok) {
                let msg = 'Invalid credentials';
                try {
                    const body = await resp.json();
                    const code = body?.error?.message || '';
                    if (code.includes('EMAIL_NOT_FOUND')) msg = 'No account found for that email.';
                    if (code.includes('INVALID_PASSWORD')) msg = 'Incorrect password.';
                    if (code.includes('USER_DISABLED')) msg = 'This account is disabled.';
                    console.error('Login error from Firebase:', code);
                } catch (_) {}
                res.set('Cache-Control', 'no-store');
                return res.status(200).render('login', { csrfToken: (typeof req.csrfToken === 'function' ? req.csrfToken() : ''), error: msg });
            }
            const data = await resp.json();
            // Trust Identity Toolkit response; avoid cross-project mismatch with Admin getUser
            req.session.user = { uid: data.localId, email: data.email || email, displayName: data.displayName || null };
            console.log(`✅ User logged in and session created for: ${email}`);
            return res.redirect('/dashboard');
        } catch (error) {
            console.error("❌ Error during login:", error);
            res.set('Cache-Control', 'no-store');
            return res.status(200).render('login', { csrfToken: (typeof req.csrfToken === 'function' ? req.csrfToken() : ''), error: 'Login failed.' });
        }
    });

    // Client-driven session login: accept Firebase ID token, create server session
    app.post('/session-login', async (req, res) => {
        try {
            const { idToken } = req.body || {};
            if (!idToken) return res.status(400).json({ error: 'Missing token' });
            const decoded = await auth.verifyIdToken(idToken);
            const userRecord = await auth.getUser(decoded.uid);
            req.session.user = { uid: userRecord.uid, email: userRecord.email, displayName: userRecord.displayName };
            return res.json({ ok: true });
        } catch (e) {
            console.error('❌ Session login failed:', e);
            return res.status(401).json({ error: 'Invalid token' });
        }
    });
    app.get('/logout', (req, res) => {
        req.session.destroy(() => res.redirect('/login'));
    });

    // Password reset
    app.get('/reset-password', csrfProtection, (req, res) => {
        res.render('reset', { csrfToken: req.csrfToken(), sent: false, error: null, user: req.session.user || null });
    });
    app.post('/reset-password', csrfProtection, async (req, res) => {
        try {
            const apiKey = process.env.FIREBASE_API_KEY;
            const { email } = req.body;
            const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ requestType: 'PASSWORD_RESET', email })
            });
            if (!resp.ok) {
                const body = await resp.json().catch(() => ({}));
                console.error('Reset error:', body);
                return res.status(400).render('reset', { csrfToken: req.csrfToken(), sent: false, error: 'Could not send reset email. Check the address.' });
            }
            return res.render('reset', { csrfToken: req.csrfToken(), sent: true, error: null });
        } catch (e) {
            console.error('Reset exception:', e);
            return res.status(500).render('reset', { csrfToken: req.csrfToken(), sent: false, error: 'Unexpected error. Try again.' });
        }
    });

    // DASHBOARD & SETTINGS ROUTES
    app.get('/dashboard', requireLogin, csrfProtection, async (req, res) => {
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
            res.render('dashboard', {
                business: businessDoc.data(),
                user: req.session.user,
                feedback: feedback,
                appUrl: appUrl, // Pass the appUrl to the dashboard
                csrfToken: req.csrfToken(),
                analytics: { total, avg, counts, conversions }
            });
        } catch (error) {
            console.error("❌ Error fetching dashboard data:", error);
            res.redirect('/login');
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
            const doc = await db.collection('businesses').doc(req.session.user.uid).get();
            const businessData = doc.data();
            const checkoutSession = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                customer: businessData.stripeCustomerId,
                line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
                mode: 'subscription',
                success_url: `${appUrl}/payment-success`,
                cancel_url: `${appUrl}/dashboard`,
            });
            res.redirect(303, checkoutSession.url);
        } catch (error) {
            console.error("❌ Error creating checkout session:", error);
            res.status(500).send("Error creating checkout session.");
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

    // Stripe Billing Portal
    app.post('/billing-portal', requireLogin, csrfProtection, async (req, res) => {
        try {
            const doc = await db.collection('businesses').doc(req.session.user.uid).get();
            const businessData = doc.data();
            const portalSession = await stripe.billingPortal.sessions.create({
                customer: businessData.stripeCustomerId,
                return_url: `${appUrl}/dashboard`
            });
            res.redirect(303, portalSession.url);
        } catch (error) {
            console.error('❌ Error creating billing portal session:', error);
            res.status(500).send('Error opening billing portal.');
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
    app.listen(PORT, HOST, () => {
        console.log(`✅ Server is running and listening on port ${PORT}`);
    });
    
