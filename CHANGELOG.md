# Changelog

All notable changes to `@fortium/identity-client`, `@fortium/identity-client/express`, and `@fortium/identity-client/fastify`.

Format follows [Keep a Changelog](https://keepachangelog.com/). This project adheres to [Semantic Versioning](https://semver.org/).

## [1.4.0] — 2026-09-29

Core, Express and Fastify all move to 1.4.0.

### Changed

- **`/widget-token` proves the user with their own access token.** The RFC 8693 exchange used to send the session's user_id as `subject_token`, so anyone holding the app's client secret could mint a token for any user (Identity #63). Both plugins now send the user's Identity access token instead, with the same `subject_token_type` URN. The route's request and response shapes are unchanged. Identity accepts both subjects during a transition and enforces the real token per client once each app has migrated.
- **`IdentityClient.requestWidgetToken(subjectAccessToken, audience, timeoutMs?)`.** The first argument is now the user's access token. A UUID there (the old user_id argument) throws a `TypeError` before any request is made. No deprecated user_id path is kept: the plugins were its only callers.
- **`TokenResult` and `RefreshResult` carry `expiresIn`**, the access token lifetime in seconds from the token response.
- **`refreshToken()` errors carry `statusCode`** when Identity answered, so a refused refresh can be told apart from an unreachable Identity.

### Added

- **A new `identity_access_token` cookie** (with `cookiePrefix` applied), signed and httpOnly, with the same options as the other auth cookies. `/callback` and `/refresh` set it, with a max age of the token's `expires_in`. It holds the token and its expiry, since Identity's access tokens are opaque. Logout, switch-account, a failed `/refresh` and a missing state cookie all clear it.
- **`/widget-token` refreshes only when it has to.** A live token is exchanged as-is. When the token is missing or expired (30 s early), the route refreshes once server-side and writes back both the new access token and the rotated refresh token. With no refresh token, or when Identity refuses the refresh with a 4xx, it answers `401` so the frontend re-authenticates. A `429`, a `5xx` or an unreachable Identity gets a retryable `503`.
- **Concurrent refreshes of one refresh token within one process share a single call**, in `/widget-token` and `/refresh` on both plugins. Refresh tokens rotate, and Identity revokes the whole grant when a used one comes back. The coalescing is in memory, so it covers requests that reach the same instance. Two instances refreshing the same token still race and can revoke the grant: an app running more than one instance needs sticky sessions, or accepts that risk. The primary mitigation is refreshing only when the access token has expired.
- `serializeAccessToken`, `usableAccessToken` and `ACCESS_TOKEN_EXPIRY_SKEW_MS` in core.

### Upgrading

- Users who logged in before the upgrade have no `identity_access_token` cookie yet. Their first widget request refreshes once to get one.
- **Express apps that set an `access_token` cookie through `extraCookies` (Talent) need no change.** The plugin uses its own distinct cookie name, so `access_token` keeps whatever value and lifetime the app gives it. An app can drop that extra cookie if it kept it only for the widget.

## [1.3.1] — 2026-09-23

### Fixed

- **Logout sends `client_id` when there is no `id_token_hint`.** When the `id_token` cookie was missing or failed to unsign, `getLogoutUrl` sent `post_logout_redirect_uri` with neither `id_token_hint` nor `client_id`, so Identity could not validate the redirect and the user stayed on its Signed Out page. `client_id` now takes the hint's place in that case. With a hint, the URL is unchanged: apps sharing a cookie domain can hold another client's ID token, and a mismatched `client_id` would make Identity reject the logout. Applies to the Express and Fastify `GET` and `POST /logout` routes, which both build the URL through core. (#15)

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
