'use strict';

const postmark = require('postmark');

const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || '';
const POSTMARK_FROM_EMAIL = process.env.POSTMARK_FROM_EMAIL || 'support@reviewsandmarketing.com';
const MESSAGE_STREAM = process.env.POSTMARK_MESSAGE_STREAM || 'outbound';
const LOGO_URL = process.env.POSTMARK_LOGO_URL || '';

const postmarkClient = POSTMARK_SERVER_TOKEN ? new postmark.ServerClient(POSTMARK_SERVER_TOKEN) : null;

function buildEmailHtml(templateName, params = {}) {
    const brand = '#2ECC71';
    const textPrimary = '#1A1A1A';
    const textSecondary = '#666666';
    const background = '#F7F7F7';
    const contentBg = '#FFFFFF';
    const font = 'Arial, Helvetica, sans-serif';

    const button = (text, href) => `
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td bgcolor="${brand}" style="border-radius:8px;">
          <a href="${href}" target="_blank" style="display:inline-block; padding:14px 28px; font-family:${font}; font-size:16px; font-weight:bold; color:#FFFFFF; text-decoration:none; border-radius:8px; background-color:${brand};">${text}</a>
        </td>
      </tr></table>`;

    const wrap = (subject, preheader, inner) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${subject}</title></head>
    <body style="margin:0; padding:0; background-color:${background};">
    <div style="display:none; font-size:1px; color:${background}; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">${preheader || ''}</div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:${background};"><tr><td align="center" style="padding:40px 12px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:100%; max-width:600px; background-color:${contentBg}; border-radius:8px;">
        <tr><td align="center" style="padding:28px 32px 8px 32px;">
          ${LOGO_URL || params.logoUrl ? `<img src="${params.logoUrl || LOGO_URL}" width="140" alt="Reviews & Marketing" style="display:block; border:0; outline:none; text-decoration:none;">` : ''}
        </td></tr>
        ${inner}
      </table>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:100%; max-width:600px; margin-top:16px;">
        <tr><td align="center" style="padding:12px; font-family:${font}; font-size:12px; color:${textSecondary};">© ${new Date().getFullYear()} Reviews & Marketing. All rights reserved.</td></tr>
      </table>
    </td></tr></table>
    </body></html>`;

    const h2 = (text) => `<tr><td style="padding:8px 32px 0 32px; font-family:${font};"><h2 style="margin:0; font-size:24px; font-weight:bold; color:${textPrimary};">${text}</h2></td></tr>`;
    const p = (text) => `<tr><td style="padding:16px 32px 0 32px; font-family:${font};"><p style="margin:0; font-size:16px; line-height:1.5; color:${textSecondary};">${text}</p></td></tr>`;

    switch (templateName) {
        case 'Email Address Verification': {
            const subject = 'Confirm Your Email Address for Reviews & Marketing';
            const pre = 'Just one more step to activate your account.';
            const inner = [
                h2('Almost there! Please confirm your email.'),
                p(`Thanks for signing up${params.businessName ? `, ${params.businessName}` : ''}! To finish creating your Reviews & Marketing account, please verify your email.`),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Verify Email Address', params.verificationUrl || '#')}</td></tr>`,
                p(`Button not working? Copy and paste this link into your browser:<br><a href="${params.verificationUrl || '#'}" style="color:${brand}; text-decoration:underline;">${params.verificationUrl || '#'}</a>`),
                p('Thanks,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        case 'Welcome / Account Creation': {
            const subject = 'Welcome to Reviews & Marketing!';
            const pre = "Your account is ready. Let's start collecting 5-star reviews.";
            const inner = [
                h2('Welcome aboard!'),
                p(`Hi ${params.businessName || ''},<br><br>Your account has been successfully created. You're all set to start turning your happy customers into powerful 5-star reviews.`),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Go to My Dashboard', params.loginUrl || '#')}</td></tr>`,
                p('Happy to have you with us,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        case 'Password Reset Request': {
            const subject = 'Reset your Reviews & Marketing password';
            const pre = 'Follow the link inside to set a new password.';
            const inner = [
                h2('Reset Your Password'),
                p('We received a request to reset the password for the Reviews & Marketing account associated with this email.<br><br>If you did not make this request, you can safely ignore this email. For security reasons, your password has not been changed.<br><br>To create a new password, click the button below. This link is only valid for the next 60 minutes.'),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Reset My Password', params.resetUrl || '#')}</td></tr>`,
                p('Thanks,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        case 'Password Changed Confirmation': {
            const subject = 'Your Reviews & Marketing password has been changed';
            const pre = 'A confirmation that your account password was updated.';
            const inner = [
                h2('Your Password Was Successfully Updated'),
                p(`This confirms that the password for your Reviews & Marketing account was changed on ${params.changedAt || ''}.`),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Sign in to Your Account', params.loginUrl || '#')}</td></tr>`,
                p('Stay secure,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        case 'New Device Login Alert': {
            const subject = 'Security Alert: New login to your account';
            const pre = 'We detected a login from a new device.';
            const kv = `<tr><td style="padding:16px 32px 0 32px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
                  <tr><td style="padding:8px 0; font-family:${font}; font-size:16px; color:${textPrimary}; width:45%;">Time</td><td style="padding:8px 0; font-family:${font}; font-size:16px; color:${textSecondary};">${params.loginTime || ''}</td></tr>
                  <tr><td style="padding:8px 0; font-family:${font}; font-size:16px; color:${textPrimary};">Approximate Location</td><td style="padding:8px 0; font-family:${font}; font-size:16px; color:${textSecondary};">${params.loginLocation || ''}</td></tr>
                  <tr><td style="padding:8px 0; font-family:${font}; font-size:16px; color:${textPrimary};">Device</td><td style="padding:8px 0; font-family:${font}; font-size:16px; color:${textSecondary};">${params.loginDevice || ''}</td></tr>
                </table>
              </td></tr>`;
            const inner = [
                h2('New Login Detected'),
                p(`Hi ${params.businessName || ''},<br><br>We detected a login to your account from a new device.`),
                kv,
                p('If this was you, you can safely disregard this email.<br><br>If you do <b>not</b> recognize this activity, please secure your account immediately by changing your password.'),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Secure Your Account', params.resetUrl || '#')}</td></tr>`,
                p('Thanks for helping us keep your account secure,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        case 'Free Trial Started Confirmation': {
            const subject = 'Your 30-Day Free Trial Has Begun!';
            const pre = 'Start collecting 5-star reviews for the next 30 days, on us.';
            const inner = [
                h2('Your Free Trial Starts Now!'),
                p(`Hi ${params.businessName || ''},<br><br>Welcome! Your 30-day free trial of the Reviews & Marketing <b>Starter Plan</b> is now active.<br><br>You have until <b>${params.trialEndsAt || ''}</b> to explore the features and see how easy it is to boost your online reputation.`),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Go to My Dashboard', params.loginUrl || '#')}</td></tr>`,
                p('Happy to have you with us,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        case 'Pro Plan Subscription & Receipt': {
            const subject = 'Welcome to Pro! Your Receipt';
            const pre = "Thanks for subscribing. Here's your receipt for $49.";
            const r = params.receipt || {};
            const table = `<tr><td style="padding:24px 32px 0 32px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
                <tr><td colspan="2" style="padding:0 0 8px 0; font-family:${font}; font-size:16px; color:${textPrimary}; font-weight:bold;">Receipt</td></tr>
                ${[['Order Number','orderNumber'],['Date','date'],['Description','description'],['Amount','amount'],['Total Paid','totalPaid'],['Paid with','paidWith']].map(([label,key])=>`<tr><td style=\"padding:8px 0; font-family:${font}; color:${textPrimary}; width:45%;\">${label}</td><td style=\"padding:8px 0; font-family:${font}; color:${textSecondary};\">${r[key]||''}</td></tr>`).join('')}
              </table>
            </td></tr>`;
            const inner = [
                h2("You're Officially a Pro!"),
                p(`Hi ${params.businessName || ''},<br><br>Thank you for subscribing to the Reviews & Marketing <b>Pro Plan</b>! Your subscription is now active.`),
                table,
                p("We're excited to see your business grow. Click below to dive back into your dashboard and explore your new Pro features."),
                `<tr><td align="center" style="padding:24px 32px 0 32px;">${button('Go to My Dashboard', params.loginUrl || '#')}</td></tr>`,
                p('Thanks for being a Pro member,<br>The Reviews & Marketing Team')
            ].join('');
            return { subject, html: wrap(subject, pre, inner) };
        }
        default:
            return { subject: 'Message from Reviews & Marketing', html: wrap('Message', '', p('')) };
    }
}

async function sendEmail({ to, template, data }) {
    try {
        if (!postmarkClient) { console.warn('Postmark not configured; skipping email.'); return { skipped: true }; }
        const { subject, html } = buildEmailHtml(template, data || {});
        const result = await postmarkClient.sendEmail({
            From: POSTMARK_FROM_EMAIL,
            To: to,
            Subject: subject,
            HtmlBody: html,
            MessageStream: MESSAGE_STREAM
        });
        return result;
    } catch (e) {
        console.error('❌ Postmark send error:', e);
        return { error: true };
    }
}

module.exports = { sendEmail, buildEmailHtml };


