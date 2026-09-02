# Changelog

All notable changes to `@fortium/identity-client`, `@fortium/identity-client/express`, and `@fortium/identity-client/fastify`.

Format follows [Keep a Changelog](https://keepachangelog.com/). This project adheres to [Semantic Versioning](https://semver.org/).

## [1.3.0] — 2026-09-02

### Added

- **Fastify: per-request `returnTo` on `GET /auth/login`.** `GET /auth/login?returnTo=/some/path` stores the path on that attempt's pending OIDC state, and the matching `/auth/callback` redirects to `frontendUrl + returnTo`. Only a validated relative path is accepted (see README); anything else is dropped and the callback falls back to `postLoginPath`, so behaviour without `returnTo` is unchanged. Overlapping logins each keep their own path. Fixes Gateway's `/resume` links, which always landed on the dashboard. (#10)
- **`sanitizeReturnTo(raw, maxLength?)`** in `@fortium/identity-client` core, and an optional `returnTo` field on `OIDCState`.

## [1.2.0] — 2026-06-17

### Fixed

- **Overlapping OIDC login attempts no longer clobber each other.** The `oidc_state` cookie holds an array of pending attempts (capped at 5, TTL-pruned) and `/auth/callback` selects the one matching the returned `state`, so a double-click or second tab no longer ends in `invalid_grant`. Cookies written by the single-object format still parse. Express and Fastify. (#8)

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
