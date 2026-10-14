# Changelog

All notable changes to `@fortium/identity-client`, `@fortium/identity-client/express`, and `@fortium/identity-client/fastify`.

Format follows [Keep a Changelog](https://keepachangelog.com/). This project adheres to [Semantic Versioning](https://semver.org/).

## [1.7.0] — 2026-10-13

Core, Express and Fastify all move to 1.7.0. Closes #25. Since 1.6.0 the default `tokenEndpointAuthMethod` is `client_secret_basic`; set `'client_secret_post'` if an app's Identity registration still says post.

### Added

- **A failed callback blocks the next `/login` for 30 seconds.** When `/callback` ends in an error, both plugins set their own short-lived signed, httpOnly cookie, `login_guard` (with `cookiePrefix`, `<prefix>_login_guard`), recording the error code and the time. While it is fresh, `GET /login` does not start an authorization request and does not redirect: it answers 200 with a page of its own (`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, no script, no style, no external resource) showing the error code and one "Try again" link to the plugin's login route with `prompt=login` (kept with a valid `returnTo` on Fastify). The link is built from `callbackUrl`, not from request input. No redirect leaves that response, so the chain ends there in every app, whatever its `/login` does (OIDC Core section 3.1.2.6). The failed callback itself still redirects to `<frontendUrl>/login?error=<code>` as in 1.6.0, so an app that handles the error never shows the page. The cookie does not depend on `oidc_state`, which may have expired or never matched, so the guard also fires after an `invalid_callback`. Every failed callback arms it, and the app's redirect for each is unchanged:
  - an OAuth error response with a matching `state` (a registered code, forwarded as in 1.6.0);
  - `invalid_callback` (no `code`, no `state`, or an error with no matching `state`);
  - `state_missing` (a code with no state cookie) and `state_mismatch` (a state that matches no pending attempt);
  - `not_authorized` (the `authorize` hook rejected the user; the app still receives the hook's reason and the email in its redirect, but the guard stores only the fixed code);
  - `callback_failed` (the token exchange or anything else in the callback threw, for example a wrong client secret or an Identity outage).

  The stored code is always one of the registered OAuth codes or one of those four fixed names. Anything else is stored as `invalid_callback`, so free text and the user's email never reach the cookie or the page.
- **An explicit user action still starts a fresh attempt.** A `/login` request with `prompt=login` or `prompt=select_account` (OIDC Core section 3.1.2.1) goes through and clears the guard. So do a successful callback and `/switch-account`.
- **After `login_required`, `interaction_required`, `consent_required` or `account_selection_required`, only `prompt=none` is refused.** OIDC Core section 3.1.2.6 defines these as the expected answers to `prompt=none`, and the client's next step is an interactive authorization request. So an app that tries `/auth/login?prompt=none`, gets `login_required`, and then sends the user to `/auth/login` (with no prompt, or `prompt=consent`) is not shown the plugin's page: that request goes through and clears the guard. Another `prompt=none` would get the same answer, so it is refused. After every other error the rule above applies unchanged. The rule is the core function `loginGuardBlocks(error, prompt)`, used by both plugins.
- **`loginGuardSeconds` plugin option** on both plugins: the window in seconds (default 30, `0` turns the guard off). A negative or non-finite value throws a `TypeError`.
- **Exports** in core: `serializeLoginGuard`, `activeLoginGuard`, `isExplicitLoginPrompt`, `loginGuardBlocks`, `loginGuardRetryUrl`, `renderLoginGuardPage`, `LOGIN_GUARD_DEFAULT_SECONDS`, `LOGIN_GUARD_PAGE_HEADERS`.

### Action for apps

One behaviour changes: for 30 seconds after any failed callback listed above, a plain `/auth/login` (no `prompt`) is answered with the plugin's page instead of starting a sign-in. The exceptions are `prompt=login` and `prompt=select_account`, and, after `login_required`, `interaction_required`, `consent_required` or `account_selection_required`, any prompt except `none`. An app whose error page links "Sign in again" to a plain `/auth/login` therefore shows the plugin's page for up to 30 seconds. Link it to `/auth/login?prompt=login` instead, which always starts a new attempt. An app that handles `/login?error=` and does not restart the flow from it needs no other change, and apps with a strict Content-Security-Policy need none: the page uses no script and no style.

## [1.6.0] — 2026-10-13

Core, Express and Fastify all move to 1.6.0. Closes #24. Also releases the two token-endpoint entries below.

### Fixed

- **`/callback` forwards the error Identity returns instead of hiding it as `invalid_callback`.** When Identity refuses a login it redirects to `/auth/callback?error=access_denied&state=...` (RFC 6749 section 4.1.2.1). Both plugins turned every callback without a `code` into `/login?error=invalid_callback`, so an app could not tell a refusal from a broken callback. A `/login` that restarts the login on an unknown error then looped between the app and Identity until the browser gave up (`ERR_TOO_MANY_REDIRECTS`; 96 refusals in 40 minutes on 2026-10-13). Now, on both plugins, a callback with an `error` and no `code` redirects to `<frontendUrl>/login?error=<code>` when `<code>` is one of the registered codes: `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`, `temporarily_unavailable` (RFC 6749 section 4.1.2.1) and `interaction_required`, `login_required`, `account_selection_required`, `consent_required`, `invalid_request_uri`, `invalid_request_object`, `request_not_supported`, `request_uri_not_supported`, `registration_not_supported` (OIDC Core section 3.1.2.6). Any other value, or a repeated `error` parameter, maps to `invalid_callback`. `error_description` and `error_uri` are never read, so they never reach a URL.
- **The error is trusted only with a matching `state`.** The returned `state` must match a pending attempt in this browser's signed `oidc_state` cookie. The matching attempt is consumed (other in-flight attempts are kept). With a missing `state`, no cookie, an invalid signature or a `state` that matches nothing, the redirect is `/login?error=invalid_callback` as before, and no cookie is changed.

### Action for apps

Render the refusal on `/login?error=access_denied` (and the other codes above) and do not restart the login from it. `/login` must not redirect to `/auth/login` when `error` is present, or a user whose account has no entitlement loops between the app and Identity. `invalid_callback`, `state_missing`, `state_mismatch` and `callback_failed` keep their meaning.

### Exports

- `sanitizeCallbackError(raw)` and `CALLBACK_ERROR_CODES` in core.

### Changed

- **Token endpoint calls authenticate with `client_secret_basic`.** `exchangeCode`, `refreshToken` and `requestWidgetToken` send `Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))` (RFC 6749 section 2.3.1) and no longer put `client_id` or `client_secret` in the body. Identity accepts Basic for every secret client today, so no consumer breaks. Refs FortiumPartners/identity#180.

### Added

- **`tokenEndpointAuthMethod` option** on `IdentityClient` and both plugins: `'client_secret_basic'` (default) or `'client_secret_post'`, for an app whose Identity registration still says post. An unknown value throws a `TypeError`. Exports the `TokenEndpointAuthMethod` type.

## [1.5.0] — 2026-09-30

Core, Express and Fastify all move to 1.5.0. Closes #20.

### Added

- **`GET /auth/login?login_hint=<address>` forwards an OIDC `login_hint`** on both plugins, so an invitation can pre-fill the invited email address at Identity's sign-in. The hint is accepted when it is a string with no control characters that is 1 to 254 characters once trimmed, and it is forwarded trimmed. Anything else (empty, too long, a control character, a repeated or nested parameter) is dropped with a debug log, like a rejected `returnTo`, and the login proceeds without it. The value is never logged, stored in a cookie or put anywhere but the authorization URL.
- **`resolveLoginHint` plugin option**, `(request) => string | undefined | Promise<string | undefined>`. Called when the query carries no valid `login_hint`, so an app can derive the hint server-side (from a signed cookie, say) instead of putting an email address in a URL. A valid query hint wins and the resolver is not called. The result is validated the same way. If the resolver throws or rejects, the plugin logs a warning and the login proceeds without a hint.
- **`IdentityClient.generateAuthorizationUrl(redirectUri, opts?)`** takes `{ loginHint?, prompt? }` (the `AuthorizationUrlOptions` type), so a server-side caller can build the URL without the plugin route. A `prompt` outside `login`, `select_account`, `consent` and `none`, or a hint `sanitizeLoginHint` rejects, is dropped.
- `sanitizeLoginHint`, `LOGIN_HINT_MAX_LENGTH` and `ALLOWED_PROMPTS` in core.

### Not changed

- Without a hint, the authorization URL, the pending OIDC state (state, nonce, PKCE verifier, `returnTo`) and `prompt` handling are byte for byte what 1.4.1 produced. The plugins now pass `prompt` to core instead of appending it themselves, with the same allowlist.
- Identity's own sign-in page still has to read `login_hint` to pre-fill the email field (FortiumPartners/identity#217). Until it does, the parameter reaches Identity and has no visible effect.

## [1.4.1] — 2026-09-29

Core, Express and Fastify all move to 1.4.1. Refs #18.

### Fixed

- **`/widget-token` only uses a subject token issued to the session user.** In 1.4.0 the subject came from the `identity_access_token` and `refresh_token` cookies, and nothing tied either to the `auth_token` session. An app route that sets only `auth_token`, or a login that returns no refresh token, could leave an earlier user's tokens in place, and the widget then minted tokens as that earlier user. Now:
  - The `identity_access_token` cookie records the `fortium_user_id` the token was issued to (`{t, exp, sub}`), taken from the validated ID token at `/callback` and `/refresh`. `/widget-token` compares it with the session user before the exchange. On a mismatch it clears the access and refresh token cookies and answers `401`.
  - The route's server-side refresh validates the returned ID token through JWKS and accepts the new tokens only when it names the session user. A different user, a missing ID token or a failed validation clears both cookies and answers `401`.
  - `/callback` clears `refresh_token` when Identity returns none, so an earlier user's refresh token never outlives a new login.
  - `/refresh` without an ID token clears `identity_access_token` instead of storing a token it cannot bind to a user.
- **A revoked but unexpired access token recovers instead of failing with `400`.** When the exchange is refused with `invalid_grant`, the route drops the stored token and refreshes once, with the same user check, then retries the exchange. If the refresh is refused or the retried exchange is refused again, it answers `401`, the frontend's re-auth signal. A refresh that cannot reach Identity is still a retryable `503`.

### Changed

- **`serializeAccessToken(accessToken, expiresIn, sub, now?)`** takes the user id as its third argument.
- **`usableAccessToken(raw, now?)`** returns `{ token, sub }` (the new `StoredAccessToken` type) instead of the bare token, and returns `null` for a cookie without `sub`.

### Upgrading

- Cookies written by 1.4.0 have no `sub`, so they are never trusted. Each user's first widget request after the upgrade refreshes once, validates the ID token, and stores a bound cookie.

### Not changed

- The refresh-rotation race when a request is sent before the browser applies a rotated `refresh_token` (#18, item 3) is still open. Refreshing only on expiry keeps it rare, and the fix, a short grace window for a just-rotated token, belongs on Identity's side.

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
