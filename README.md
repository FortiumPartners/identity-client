# @fortium/identity-client

Shared OIDC client for Fortium Identity. Three packages:

- **`@fortium/identity-client`** — Core OIDC mechanics (framework-agnostic)
- **`@fortium/identity-client/fastify`** — Fastify plugin with auth routes + cookies
- **`@fortium/identity-client/express`** — Express plugin with auth routes + cookies

## Installation

```json
{
  "@fortium/identity-client": "github:FortiumPartners/identity-client"
}
```

Pin to a specific commit to avoid CDN caching issues:

```json
{
  "@fortium/identity-client": "https://github.com/FortiumPartners/identity-client/tarball/<commit-sha>"
}
```

## Express Plugin Usage

```javascript
import { createIdentityRouter } from '@fortium/identity-client/express';
import cookieParser from 'cookie-parser';

app.use(cookieParser(JWT_SECRET)); // Required — cookies are signed

const authRouter = createIdentityRouter({
  issuer: 'https://identity.fortiumsoftware.com',
  clientId: 'my-app',
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  callbackUrl: 'https://app.example.com/auth/callback',
  frontendUrl: 'https://app.example.com',
  jwtSecret: JWT_SECRET,
  sessionIssuer: 'my-app',

  authorize: async (claims) => {
    // Check authorization, return extra session data
    return { role: 'admin', name: claims.name };
  },

  getMe: async (session) => {
    // Build /auth/me response
    return { user: { id: session.fortiumUserId, email: session.email } };
  },
});

app.use('/auth', authRouter);
```

### requireAuth middleware (Express)

```javascript
import { requireAuth } from '@fortium/identity-client/express';

const auth = requireAuth({ jwtSecret: JWT_SECRET, issuer: 'my-app' });

app.get('/api/protected', auth, (req, res) => {
  const user = req.user; // { fortiumUserId, email, ...extra }
  res.json({ user });
});
```

## Fastify Plugin Usage

```typescript
import { identityPlugin } from '@fortium/identity-client/fastify';

await app.register(identityPlugin, {
  issuer: config.IDENTITY_ISSUER,
  clientId: config.IDENTITY_CLIENT_ID,
  clientSecret: config.IDENTITY_CLIENT_SECRET,
  callbackUrl: config.IDENTITY_CALLBACK_URL,
  frontendUrl: config.FRONTEND_URL,
  jwtSecret: config.JWT_SECRET,
  sessionIssuer: 'my-app',

  authorize: async (claims) => {
    return { role: 'admin' };
  },

  getMe: async (session) => {
    return { user: { id: session.fortiumUserId, email: session.email } };
  },
});
```

### requireAuth middleware (Fastify)

```typescript
import { requireAuth } from '@fortium/identity-client/fastify';

const auth = requireAuth({ jwtSecret: config.JWT_SECRET, issuer: 'my-app' });

app.get('/api/protected', { preHandler: [auth] }, async (request, reply) => {
  const user = request.user!; // { fortiumUserId, email, ...extra }
});
```

## Routes (both plugins)

Both plugins register the same routes:

| Route | Method | Description |
|---|---|---|
| `/login` | GET | Redirect to Identity for OIDC login |
| `/callback` | GET | Handle OIDC callback, set session cookies |
| `/me` | GET | Return current user from session |
| `/refresh` | POST | Exchange refresh token for new tokens |
| `/logout` | POST | Clear cookies, return `{ logoutUrl }` |
| `/logout` | GET | Clear cookies, redirect to Identity logout |

Mount at `/auth` to get `/auth/login`, `/auth/callback`, etc.

## Cookies

Both plugins set the same signed httpOnly cookies:

| Cookie | Contents | Max Age |
|--------|----------|---------|
| `auth_token` | Session JWT (HS256) | 24 hours |
| `id_token` | Raw OIDC ID token | 24 hours |
| `refresh_token` | OIDC refresh token | 7 days |

All cookies are signed, httpOnly, sameSite=lax, secure in production.

## Plugin Options

| Option | Required | Description |
|--------|----------|-------------|
| `issuer` | Yes | Identity issuer URL |
| `clientId` | Yes | OIDC client ID |
| `clientSecret` | Yes | OIDC client secret |
| `callbackUrl` | Yes | Full callback URL |
| `frontendUrl` | Yes | Frontend URL for redirects |
| `jwtSecret` | Yes | Secret for session JWTs and cookie signing |
| `sessionIssuer` | Yes | Issuer name for session JWTs |
| `sessionExpiresIn` | No | Session JWT expiry (default: `'24h'`) |
| `cookiePrefix` | No | Prefix for cookie names |
| `postLoginPath` | No | Redirect path after login (default: `/dashboard`) |
| `postLogoutPath` | No | Redirect path after logout (default: `/login`) |
| `authorize` | No | Hook called after OIDC auth — check permissions, return extra session data |
| `getMe` | No | Hook to build `/me` response |
| `extraCookies` | No | Express only — set additional cookies from tokens (e.g., access token for backend forwarding) |

## Core Package Usage

For frameworks without a plugin, use the core package directly:

```typescript
import { IdentityClient, createSessionToken, verifySessionToken } from '@fortium/identity-client';

const client = new IdentityClient({
  issuer: 'https://identity.fortiumsoftware.com',
  clientId: 'my-client-id',
  clientSecret: 'my-client-secret',
});

// Generate auth URL
const { url, state } = await client.generateAuthorizationUrl('https://app.example.com/callback');

// Exchange code for tokens
const { claims, idToken, refreshToken } = await client.exchangeCode(code, state);

// Create session JWT
const token = await createSessionToken(
  { fortiumUserId: claims.fortium_user_id, email: claims.email },
  { jwtSecret: 'secret', issuer: 'my-app' }
);

// Verify session JWT
const session = await verifySessionToken(token, { jwtSecret: 'secret', issuer: 'my-app' });
```

## Development

```bash
npm install --ignore-scripts
npm run build    # Builds core, fastify, and express packages
```

## Packages

```
packages/
├── core/       — IdentityClient, session JWT utilities, types
├── fastify/    — Fastify plugin (identityPlugin, requireAuth)
└── express/    — Express plugin (createIdentityRouter, requireAuth)
```
