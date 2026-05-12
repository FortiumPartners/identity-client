# Changelog

All notable changes to `@fortium/identity-client`, `@fortium/identity-client/express`, and `@fortium/identity-client/fastify`.

Format follows [Keep a Changelog](https://keepachangelog.com/). This project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-05-12

### Added

- **RFC 8693 Token Exchange consumer route** on both Express (`/auth/widget-token`) and Fastify (`GET /auth/widget-token`) plugins. Authenticated users can request a narrow-audience JWT to hand to a downstream service (e.g. the Ideas widget). Returns:
  ```json
  { "accessToken": "<jwt>", "expiresIn": 300, "tokenType": "Bearer", "audience": "<resource>" }
  ```
  Reuses the existing plugin `clientId` + `clientSecret` (the app's own OIDC client credentials) — no new env vars required. Requires Identity-side allowlist (Identity migration 033/034 + the `allowed_exchange_audiences` column on the `oidc_clients` row).
- **`IdentityClient.requestWidgetToken(subjectUserId, audience, timeoutMs?)`** in `@fortium/identity-client` core. Powers the plugin routes; also usable directly for framework-agnostic consumers.

### Configuration required on Identity (admin)

The calling app's `oidc_clients` row must:
1. Include `urn:ietf:params:oauth:grant-type:token-exchange` in its `grant_types` array.
2. Have the requested audience listed in its `allowed_exchange_audiences` column.

Without both, Identity returns `invalid_request` (missing grant type) or `invalid_target` (audience not allowlisted) — the plugin forwards these to the caller verbatim.

See Identity repo's `docs/WIDGET_TOKEN_EXCHANGE.md` for the full contract.

### Wire protocol

```
GET /auth/widget-token?audience=ideas-api
Cookie: auth_token=<signed-session>

→ 200 OK { accessToken, expiresIn, tokenType, audience }
   401 if no/invalid session
   400 if audience missing or Identity returns 4xx (forwarded)
   503 if Identity unreachable
```

## [1.0.0] — initial release

- OIDC PKCE login + callback + session management
- `/login`, `/callback`, `/me`, `/refresh`, `/logout`, `/switch-account` routes (Express + Fastify)
- M2M token verification via `createM2MAuth()`
- Admin API client (`@fortium/identity-client/admin`)
- Cookie session signing via `@fastify/cookie` or `cookie-parser`
