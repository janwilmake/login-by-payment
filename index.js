/**
 * Smoother Auth - Login by Payment
 * 
 * A proof of concept for authentication using Stripe payments.
 * Users authenticate by making a small payment, which creates a secure session.
 * 
 * Flow:
 * 1. User visits /login and gets redirected to Stripe payment
 * 2. After payment, Stripe webhook creates secure session
 * 3. User can access protected content with their payment-verified identity
 * 4. Session persists across devices using payment method fingerprinting
 * 
 * Environment Variables Required:
 * - STRIPE_SECRET: Your Stripe secret key
 * - STRIPE_WEBHOOK_SIGNING_SECRET: Webhook endpoint secret
 * - STRIPE_PAYMENT_LINK: Your Stripe payment link URL
 * - SESSION_SECRET: Secret for signing session tokens (minimum 32 chars)
 */

import { Stripe } from 'stripe';

/**
 * In-memory session store (replace with KV or D1 in production)
 * Structure: { sessionId: { email, name, paymentMethodFingerprint, createdAt } }
 */
const sessions = new Map();

/**
 * Generate a secure session ID
 * @returns {string} Random session identifier
 */
function generateSessionId() {
  return crypto.randomUUID();
}

/**
 * Create HMAC signature for session validation
 * @param {string} sessionId - Session identifier to sign
 * @param {string} secret - Signing secret
 * @returns {Promise<string>} Base64 encoded signature
 */
async function signSession(sessionId, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(sessionId)
  );
  
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

/**
 * Verify session signature
 * @param {string} sessionId - Session identifier
 * @param {string} signature - Signature to verify
 * @param {string} secret - Signing secret
 * @returns {Promise<boolean>} Whether signature is valid
 */
async function verifySession(sessionId, signature, secret) {
  try {
    const expectedSignature = await signSession(sessionId, secret);
    return expectedSignature === signature;
  } catch {
    return false;
  }
}

/**
 * Parse cookies from request header
 * @param {string} cookieHeader - Cookie header value
 * @returns {Object} Parsed cookies as key-value pairs
 */
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  
  cookieHeader.split(';').forEach(cookie => {
    const [name, value] = cookie.split('=').map(c => c.trim());
    if (name && value) {
      cookies[name] = value;
    }
  });
  
  return cookies;
}

/**
 * Get current user session from request
 * @param {Request} request - Incoming request
 * @param {Object} env - Environment variables
 * @returns {Object|null} User session data or null if invalid
 */
async function getCurrentUser(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const sessionId = cookies.session_id;
  const signature = cookies.session_sig;
  
  if (!sessionId || !signature) return null;
  
  const isValid = await verifySession(sessionId, signature, env.SESSION_SECRET);
  if (!isValid) return null;
  
  return sessions.get(sessionId) || null;
}

/**
 * Create secure session cookies
 * @param {string} sessionId - Session identifier
 * @param {string} signature - Session signature
 * @param {URL} url - Request URL for domain
 * @param {Object} env - Environment variables
 * @returns {string[]} Array of Set-Cookie header values
 */
function createSessionCookies(sessionId, signature, url, env) {
  const isLocalhost = url.hostname === 'localhost';
  const securePart = isLocalhost ? '' : ' Secure;';
  const domainPart = isLocalhost ? '' : ` Domain=${url.hostname};`;
  const cookieOptions = `${domainPart} HttpOnly; Path=/;${securePart} Max-Age=2592000; SameSite=Lax`;
  
  return [
    `session_id=${sessionId};${cookieOptions}`,
    `session_sig=${signature};${cookieOptions}`
  ];
}

/**
 * Handle login endpoint - redirect to Stripe payment
 * @param {Request} request - Incoming request
 * @param {Object} env - Environment variables
 * @returns {Response} Redirect to Stripe payment link
 */
async function handleLogin(request, env) {
  const url = new URL(request.url);
  
  // Generate a temporary session ID to track this login attempt
  const tempSessionId = generateSessionId();
  
  // Append session ID to payment link for tracking
  const paymentUrl = new URL(env.STRIPE_PAYMENT_LINK);
  paymentUrl.searchParams.set('client_reference_id', tempSessionId);
  
  return new Response(null, {status:302,headers:{Location:paymentUrl.toString()}});
}

/**
 * Handle logout endpoint - clear session cookies
 * @param {Request} request - Incoming request
 * @param {Object} env - Environment variables
 * @returns {Response} Redirect to home with cleared cookies
 */
function handleLogout(request, env) {
  const url = new URL(request.url);
  const isLocalhost = url.hostname === 'localhost';
  const securePart = isLocalhost ? '' : ' Secure;';
  const domainPart = isLocalhost ? '' : ` Domain=${url.hostname};`;
  const expiredCookie = `${domainPart} HttpOnly; Path=/;${securePart} Max-Age=0; SameSite=Lax`;
  
  const headers = new Headers();
  headers.append('Set-Cookie', `session_id=;${expiredCookie}`);
  headers.append('Set-Cookie', `session_sig=;${expiredCookie}`);
  headers.append('Location', '/');
  
  return new Response(null, { status: 302, headers });
}

/**
 * Handle Stripe webhook for payment completion
 * @param {Request} request - Incoming webhook request
 * @param {Object} env - Environment variables
 * @returns {Response} Webhook response
 */
async function handleStripeWebhook(request, env) {
  if (!request.body) {
    return new Response('No body provided', { status: 400 });
  }

  // Read the raw body for signature verification
  const rawBody = await request.text();
  const stripe = new Stripe(env.STRIPE_SECRET, { apiVersion: '2025-03-31.basil' });
  
  const stripeSignature = request.headers.get('stripe-signature');
  if (!stripeSignature) {
    return new Response('No stripe signature', { status: 400 });
  }

  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      rawBody,
      stripeSignature,
      env.STRIPE_WEBHOOK_SIGNING_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return new Response(`Webhook error: ${err.message}`, { status: 400 });
  }

  // Handle successful payment
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    
    if (session.payment_status !== 'paid') {
      return new Response('Payment not completed', { status: 400 });
    }

    const { client_reference_id, customer_details } = session;
    
    if (!client_reference_id || !customer_details?.email) {
      return new Response('Missing required session data', { status: 400 });
    }

    try {
      // Get payment method details for fingerprinting
      const paymentIntent = await stripe.paymentIntents.retrieve(session.payment_intent);
      const charge = await stripe.charges.retrieve(paymentIntent.latest_charge);
      const paymentMethodFingerprint = charge.payment_method_details?.card?.fingerprint;

      // Check if user already has a session with this payment method
      let existingSessionId = null;
      for (const [sessionId, sessionData] of sessions.entries()) {
        if (sessionData.paymentMethodFingerprint === paymentMethodFingerprint) {
          existingSessionId = sessionId;
          break;
        }
      }

      const sessionId = existingSessionId || client_reference_id;
      
      // Store session data
      sessions.set(sessionId, {
        email: customer_details.email,
        name: customer_details.name || null,
        paymentMethodFingerprint,
        createdAt: new Date().toISOString()
      });

      console.log(`Session created for ${customer_details.email} with ID: ${sessionId}`);
      
      return new Response('Payment processed successfully', { status: 200 });
    } catch (error) {
      console.error('Error processing payment:', error);
      return new Response('Error processing payment', { status: 500 });
    }
  }

  return new Response('Event not handled', { status: 200 });
}

/**
 * Handle home page - show login status and user details
 * @param {Request} request - Incoming request
 * @param {Object} env - Environment variables
 * @returns {Response} HTML response with user status
 */
async function handleHome(request, env) {
  const url = new URL(request.url);
  const user = await getCurrentUser(request, env);
  
  // Check if this is a redirect from Stripe with a session ID
  const tempSessionId = url.searchParams.get('session_id') || url.searchParams.get('client_reference_id');
  let newSessionCookies = [];
  
  if (tempSessionId && sessions.has(tempSessionId) && !user) {
    // User just completed payment, set session cookies
    const signature = await signSession(tempSessionId, env.SESSION_SECRET);
    newSessionCookies = createSessionCookies(tempSessionId, signature, url, env);
  }

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smoother Auth - Login by Payment</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            max-width: 600px;
            margin: 40px auto;
            padding: 0 20px;
            line-height: 1.6;
            color: #333;
        }
        .card {
            background: #fff;
            border: 1px solid #e1e5e9;
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .status {
            padding: 12px 16px;
            border-radius: 6px;
            margin: 16px 0;
            font-weight: 500;
        }
        .status.authenticated {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status.anonymous {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .user-details {
            background: #f8f9fa;
            padding: 16px;
            border-radius: 6px;
            margin: 16px 0;
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            background: #635bff;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            margin: 8px 8px 8px 0;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        .button:hover {
            background: #5147e6;
        }
        .button.secondary {
            background: #6c757d;
        }
        .button.secondary:hover {
            background: #545b62;
        }
        h1 {
            color: #635bff;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 24px;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>🔐 Smoother Auth</h1>
        <p class="subtitle">Login by Payment Proof of Concept</p>
        
        ${user ? `
            <div class="status authenticated">
                ✅ Authenticated via Stripe Payment
            </div>
            
            <div class="user-details">
                <h3>Your Details</h3>
                <p><strong>Email:</strong> ${user.email}</p>
                <p><strong>Name:</strong> ${user.name || 'Not provided'}</p>
                <p><strong>Session Created:</strong> ${new Date(user.createdAt).toLocaleString()}</p>
            </div>
            
            <a href="/logout" class="button secondary">Logout</a>
        ` : `
            <div class="status anonymous">
                ❌ Not authenticated
            </div>
            
            <p>To access this application, please authenticate by making a small payment through Stripe. Your payment method will be used to verify your identity across sessions.</p>
            
            <a href="/login" class="button">🔗 Login with Stripe Payment</a>
        `}
        
        <hr style="margin: 24px 0; border: none; border-top: 1px solid #e1e5e9;">
        
        <h3>How it works</h3>
        <ol>
            <li>Click "Login with Stripe Payment" to make a small payment</li>
            <li>Your payment method creates a unique fingerprint for authentication</li>
            <li>Access the application with your verified identity</li>
            <li>Future logins from the same payment method will be automatic</li>
        </ol>
    </div>
</body>
</html>`;

  const headers = new Headers({
    'Content-Type': 'text/html',
  });
  
  // Add session cookies if we just created a session
  newSessionCookies.forEach(cookie => {
    headers.append('Set-Cookie', cookie);
  });

  return new Response(html, { headers });
}

/**
 * Main request handler
 * @param {Request} request - Incoming request
 * @param {Object} env - Environment variables
 * @param {ExecutionContext} ctx - Execution context
 * @returns {Response} HTTP response
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Route handling
      switch (path) {
        case '/':
          return await handleHome(request, env);
        
        case '/login':
          return await handleLogin(request, env);
        
        case '/logout':
          return handleLogout(request, env);
        
        case '/stripe-webhook':
          return await handleStripeWebhook(request, env);
        
        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (error) {
      console.error('Request handler error:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};