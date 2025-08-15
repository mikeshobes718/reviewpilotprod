'use strict';

exports.handler = async (event) => {
  try {
    console.log('CustomMessage event (redacted):', JSON.stringify({
      triggerSource: event && event.triggerSource,
      region: event && event.region,
      userPoolId: event && event.userPoolId,
      userName: event && event.userName,
      request: event && event.request ? {
        type: event.request.type,
        codeParameter: event.request.codeParameter,
        userAttributes: { email: event.request.userAttributes && event.request.userAttributes.email }
      } : null
    }));

    const token = process.env.POSTMARK_SERVER_TOKEN;
    const fromEmail = process.env.POSTMARK_FROM_EMAIL || 'support@reviewsandmarketing.com';
    if (!token) {
      console.error('POSTMARK_SERVER_TOKEN missing');
      return event;
    }

    const to = event?.request?.userAttributes?.email;
    const code = event?.request?.codeParameter || '';
    const trigger = String(event?.triggerSource || '');

    if (!to) {
      console.error('Recipient email missing in event');
      return event;
    }

    if (trigger === 'CustomMessage_ForgotPassword') {
      const subject = 'Reset your password code';
      const intro = 'Use this code to reset your password:';
      const textBody = `${intro}\n\n${code}\n\nIf you didn't request this, you can ignore this email.`;
      const htmlBody = `<!doctype html><html><body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5;color:#111">
        <p>${intro}</p>
        <p style="font-size:20px;font-weight:700;letter-spacing:2px;background:#F3F4F6;display:inline-block;padding:8px 12px;border-radius:6px">${code}</p>
        <p style="color:#6B7280">If you didn't request this, you can safely ignore this email.</p>
      </body></html>`;

      const resp = await fetch('https://api.postmarkapp.com/email', {
        method: 'POST',
        headers: {
          'X-Postmark-Server-Token': token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          From: fromEmail,
          To: to,
          Subject: subject,
          TextBody: textBody,
          HtmlBody: htmlBody,
          MessageStream: process.env.POSTMARK_MESSAGE_STREAM || 'outbound'
        })
      });

      if (!resp.ok) {
        const body = await resp.text();
        console.error('Postmark send failed', resp.status, body);
      } else {
        try { console.log('Postmark send ok', await resp.json()); } catch(_) { console.log('Postmark send ok'); }
      }

      // Prevent Cognito default email from sending
      if (event && event.response) {
        event.response.emailMessage = null;
        event.response.emailSubject = null;
        event.response.smsMessage = null;
      }
    }

    return event;
  } catch (e) {
    console.error('CustomMessage fatal error:', e);
    return event;
  }
};


