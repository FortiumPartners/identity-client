# @fortium/identity-client

Shared OIDC client for Fortium Identity. Two packages:

- **`@fortium/identity-client`** — Core OIDC mechanics (framework-agnostic)
- **`@fortium/identity-client/fastify`** — Fastify plugin with auth routes + cookies

## Installation (in consuming apps)

```json
{
  "@fortium/identity-client": "github:FortiumPartners/identity-client"
}
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
    // Check authorization, upsert records, return extra session data
    return { role: 'admin' };
  },

  getMe: async (session) => {
    // Build /auth/me response
    return { user: { id: session.fortiumUserId, email: session.email } };
  },
});
```

### Routes registered automatically

| Route | Method | Description |
|---|---|---|
| `/auth/login` | GET | Redirect to Identity for OIDC login |
| `/auth/callback` | GET | Handle OIDC callback, set session cookies |
| `/auth/me` | GET | Return current user from session |
| `/auth/refresh` | POST | Exchange refresh token for new tokens |
| `/auth/logout` | POST | Clear cookies, return `{ logoutUrl }` |
| `/auth/logout` | GET | Clear cookies, redirect to Identity logout |

### requireAuth middleware

```typescript
import { requireAuth } from '@fortium/identity-client/fastify';

const auth = requireAuth({ jwtSecret: config.JWT_SECRET, issuer: 'my-app' });

app.get('/api/protected', { preHandler: [auth] }, async (request, reply) => {
  const user = request.user!; // { fortiumUserId, email, ...extra }
});
```

## Core Package Usage (Express/other frameworks)

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

// Create session
const token = await createSessionToken(
  { fortiumUserId: claims.fortium_user_id, email: claims.email },
  { jwtSecret: 'secret', issuer: 'my-app' }
);
```
