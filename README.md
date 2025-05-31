# 🔐 Smoother Auth - Login by Payment

A proof of concept for authentication using Stripe payments. Users authenticate by making a small payment, which creates a secure session based on their payment method fingerprint.

## 🚀 Features

- **No traditional signup/login forms** - authenticate via Stripe payment
- **Cross-device sessions** - same payment method works across devices
- **Secure session management** - HMAC-signed session cookies
- **Simple implementation** - single JavaScript file with clear documentation
- **Cloudflare Workers ready** - optimized for edge deployment

## 🏗️ How It Works

1. **User visits `/login`** - gets redirected to Stripe payment link
2. **User completes payment** - Stripe webhook processes the payment
3. **Session created** - based on payment method fingerprint
4. **User authenticated** - can access protected content
5. **Cross-device access** - same payment method = same session

## 🛠️ Setup

### 1. Environment Variables

Create a `.dev.vars` file with the following variables:

```env
STRIPE_SECRET=sk_test_...
STRIPE_WEBHOOK_SIGNING_SECRET=whsec_...
STRIPE_PAYMENT_LINK=https://buy.stripe.com/...
SESSION_SECRET=your-32-character-minimum-secret-key
```

### 2. Stripe Configuration

1. **Create a Payment Link** in your Stripe dashboard
2. **Set up a webhook endpoint** pointing to `https://yourdomain.com/stripe-webhook`
3. **Subscribe to event**: `checkout.session.completed`
4. **Copy the webhook signing secret** to your environment variables

### 3. Deploy

```bash
# Install dependencies
npm install

# Development
npm run dev

# Deploy to Cloudflare Workers
npm run deploy
```

## 🔒 Security Considerations

- **Session signing**: Uses HMAC-SHA256 to sign session IDs
- **HttpOnly cookies**: Prevents XSS access to session data
- **Secure cookies**: HTTPS-only in production
- **Payment verification**: Validates Stripe webhook signatures
- **Fingerprinting**: Uses payment method fingerprints for identity

## 📡 API Endpoints

- **`GET /`** - Home page showing authentication status
- **`GET /login`** - Redirects to Stripe payment link
- **`GET /logout`** - Clears session and redirects home
- **`POST /stripe-webhook`** - Handles Stripe payment webhooks

## 💡 Use Cases

- **Premium content access** - pay once, access forever
- **API authentication** - developers pay for API access
- **Membership verification** - prove membership through payment
- **Age verification** - payment method as identity proof
- **Geographic verification** - payment method location validation

## ⚠️ Limitations

- **In-memory storage** - sessions lost on worker restart (use KV/D1 for production)
- **Single payment type** - currently only supports card payments
- **No refunds handling** - doesn't handle refunded payments
- **Basic session management** - no session expiry or rotation

## 🔄 Production Considerations

For production use, consider:

1. **Persistent storage** - Replace Map with Cloudflare KV or D1
2. **Session expiry** - Implement automatic session cleanup
3. **Payment validation** - Handle refunds and chargebacks
4. **Rate limiting** - Prevent abuse of payment endpoints
5. **Error handling** - Robust error responses and logging
6. **Multiple payment methods** - Support for different payment types

## 📜 License

MIT - Feel free to use this concept in your projects!

## 🤝 Contributing

This is a proof of concept. Feel free to fork and improve upon the idea!