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

    // --- 2. INITIALIZE THE APP ---
    const app = express();
    const PORT = process.env.PORT || 3000;
    const HOST = '0.0.0.0'; // Necessary for some hosting platforms

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
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.set('view engine', 'ejs');
    app.use(cookieParser());
    app.use(session({
        secret: process.env.SESSION_SECRET || 'a-super-secret-key-that-you-should-change',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: process.env.NODE_ENV === 'production' } // Use secure cookies in production
    }));

    const requireLogin = (req, res, next) => {
        if (req.session.user) {
            next();
        } else {
            res.redirect('/login');
        }
    };

    // --- 5. DEFINE THE ROUTES (THE "URLS") ---
    const appUrl = process.env.HEROKU_APP_NAME ? `https://${process.env.HEROKU_APP_NAME}.herokuapp.com` : `http://localhost:${PORT}`;

    // AUTH ROUTES
    app.get('/', (req, res) => res.render('index'));
    app.get('/signup', (req, res) => res.render('signup'));
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
            res.status(500).send("Something went wrong during signup.");
        }
    });
    app.get('/login', (req, res) => res.render('login'));
    app.post('/login', async (req, res) => {
        try {
            const { email } = req.body;
            const userRecord = await auth.getUserByEmail(email);
            req.session.user = { uid: userRecord.uid, email: userRecord.email, displayName: userRecord.displayName };
            console.log(`✅ User logged in and session created for: ${email}`);
            res.redirect('/dashboard');
        } catch (error) {
            console.error("❌ Error during login:", error);
            res.status(401).send("Login failed.");
        }
    });
    app.get('/logout', (req, res) => {
        req.session.destroy(() => res.redirect('/login'));
    });

    // DASHBOARD & SETTINGS ROUTES
    app.get('/dashboard', requireLogin, async (req, res) => {
        try {
            const businessDoc = await db.collection('businesses').doc(req.session.user.uid).get();
            if (!businessDoc.exists) throw new Error('No business data found.');
            const feedbackSnapshot = await db.collection('businesses').doc(req.session.user.uid).collection('feedback').get();
            const feedback = feedbackSnapshot.docs.map(doc => doc.data());
            res.render('dashboard', {
                business: businessDoc.data(),
                user: req.session.user,
                feedback: feedback,
                appUrl: appUrl // Pass the appUrl to the dashboard
            });
        } catch (error) {
            console.error("❌ Error fetching dashboard data:", error);
            res.redirect('/login');
        }
    });

    app.post('/update-settings', requireLogin, async (req, res) => {
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
    app.post('/create-checkout-session', requireLogin, async (req, res) => {
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
            await db.collection('businesses').doc(req.session.user.uid).update({
                subscriptionStatus: 'active'
            });
            console.log(`✅ Subscription activated for user: ${req.session.user.uid}`);
            res.redirect('/dashboard');
        } catch (error) {
            console.error("❌ Error updating subscription status:", error);
            res.status(500).send("Error updating your subscription.");
        }
    });

    // PUBLIC RATING AND FEEDBACK ROUTES
    app.get('/rate/:businessId', async (req, res) => {
        try {
            const businessId = req.params.businessId;
            const doc = await db.collection('businesses').doc(businessId).get();
            if (!doc.exists || doc.data().subscriptionStatus !== 'active') {
                return res.status(404).send("This business is not currently active.");
            }
            const businessData = { ...doc.data(), uid: doc.id };
            res.render('rate', { business: businessData });
        } catch (error) {
            console.error("❌ Error fetching rating page:", error);
            res.status(500).send("Could not load rating page.");
        }
    });

    app.post('/submit-feedback/:businessId', async (req, res) => {
        try {
            const businessId = req.params.businessId;
            const feedbackData = req.body;
            await db.collection('businesses').doc(businessId).collection('feedback').add({
                ...feedbackData,
                createdAt: new Date().toISOString()
            });
            console.log(`✅ Feedback received for business: ${businessId}`);
            res.status(200).json({ message: 'Feedback submitted successfully.' });
        } catch (error) {
            console.error("❌ Error submitting feedback:", error);
            res.status(500).json({ message: 'Failed to submit feedback.' });
        }
    });

    // --- 6. START THE SERVER ---
    app.listen(PORT, HOST, () => {
        console.log(`✅ Server is running and listening on port ${PORT}`);
    });
    
