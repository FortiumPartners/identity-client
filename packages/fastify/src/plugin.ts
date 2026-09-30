/**
 * Fastify plugin for Fortium Identity OIDC authentication.
 *
 * Registers auth routes (/auth/login, /auth/callback, /auth/me, etc.)
 * and enforces the standard OIDC flow with signed httpOnly cookies.
 *
 * Apps customize behavior via hooks (authorize, getMe) — not by
 * reimplementing the OIDC flow.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import '@fastify/cookie'; // Type augmentations for cookies
import {
  IdentityClient,
  createSessionToken,
  verifySessionToken,
  verifyM2MToken,
  parsePendingStates,
  appendPendingState,
  selectPendingState,
  removePendingState,
  serializePendingStates,
  sanitizeReturnTo,
  sanitizeLoginHint,
  serializeAccessToken,
  usableAccessToken,
} from '@fortium/identity-client';
import type {
  FortiumClaims,
  SessionPayload,
  M2MAuthOptions,
  M2MTokenPayload,
  RefreshResult,
} from '@fortium/identity-client';

export interface IdentityPluginOptions {
  /** Identity issuer URL (e.g., https://identity.fortiumsoftware.com) */
  issuer: string;
  /** OIDC client ID */
  clientId: string;
  /** OIDC client secret */
  clientSecret: string;
  /** Full callback URL (e.g., https://app.example.com/auth/callback) */
  callbackUrl: string;
  /** Frontend URL for redirects after login/logout */
  frontendUrl: string;
  /** Secret for signing session JWTs */
  jwtSecret: string;
  /** Issuer name for session JWTs (e.g., 'gateway', 'payouts') */
  sessionIssuer: string;
  /** Session JWT expiry (default: '24h') */
  sessionExpiresIn?: string;
  /** Cookie name prefix (default: '') */
  cookiePrefix?: string;
  /** Where to redirect after successful login (default: frontendUrl + '/dashboard') */
  postLoginPath?: string;
  /** Where Identity redirects after logout (default: frontendUrl + '/login') */
  postLogoutPath?: string;
  /** Cookie domain for cross-subdomain sharing (e.g., '.lxp.fortiumsoftware.com') */
  cookieDomain?: string;
  /**
   * SameSite attribute for auth cookies (default: 'lax').
   * Set to 'none' when the frontend and API are on cross-site origins
   * (e.g., separate onrender.com subdomains, which are cross-site because
   * onrender.com is on the Public Suffix List). 'none' requires Secure,
   * which the plugin already sets in production.
   */
  cookieSameSite?: 'lax' | 'strict' | 'none';

  /**
   * Called after Identity authenticates the user.
   * Use to check authorization (e.g., admin allowlist) and return extra session data.
   * Throw to reject the login. Return extra fields to include in the session JWT.
   */
  authorize?: (claims: FortiumClaims) => Promise<Record<string, unknown>>;

  /**
   * Called by GET /auth/me to build the response from the session.
   * If not provided, returns { user: { fortiumUserId, email } }.
   */
  getMe?: (session: SessionPayload) => Promise<Record<string, unknown>>;

  /**
   * Called by GET /auth/login when the query carries no valid `login_hint`,
   * to derive one server-side (e.g. from a signed cookie) instead of putting
   * an email address in a URL. The result is validated like the query
   * parameter and dropped when invalid. If it throws, the login proceeds
   * without a hint.
   */
  resolveLoginHint?: (request: FastifyRequest) => string | undefined | Promise<string | undefined>;
}

// Cookie name helpers
function cookieName(prefix: string, name: string): string {
  return prefix ? `${prefix}_${name}` : name;
}

async function identityPluginImpl(app: FastifyInstance, opts: IdentityPluginOptions) {
  const prefix = opts.cookiePrefix || '';
  const OIDC_STATE_COOKIE = cookieName(prefix, 'oidc_state');
  const AUTH_TOKEN_COOKIE = cookieName(prefix, 'auth_token');
  const ID_TOKEN_COOKIE = cookieName(prefix, 'id_token');
  const REFRESH_TOKEN_COOKIE = cookieName(prefix, 'refresh_token');
  const ACCESS_TOKEN_COOKIE = cookieName(prefix, 'identity_access_token');

  const isProd = process.env.NODE_ENV === 'production';

  const client = new IdentityClient({
    issuer: opts.issuer,
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
  });

  const sessionConfig = {
    jwtSecret: opts.jwtSecret,
    issuer: opts.sessionIssuer,
    expiresIn: opts.sessionExpiresIn || '24h',
  };

  const postLoginRedirect = opts.postLoginPath
    ? `${opts.frontendUrl}${opts.postLoginPath}`
    : `${opts.frontendUrl}/dashboard`;

  const postLogoutRedirect = opts.postLogoutPath
    ? `${opts.frontendUrl}${opts.postLogoutPath}`
    : `${opts.frontendUrl}/login`;

  // Helper: standard cookie options
  const sameSiteAttr = opts.cookieSameSite || 'lax';
  // SameSite=None requires Secure per browser spec — force secure in that case
  // even outside production (still gated by HTTPS on Render etc.).
  const cookieSecure = isProd || sameSiteAttr === 'none';
  function cookieOpts(maxAge: number) {
    const base: Record<string, unknown> = {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: sameSiteAttr,
      maxAge,
      path: '/',
      signed: true,
    };
    if (opts.cookieDomain) {
      base.domain = opts.cookieDomain;
    }
    return base;
  }

  // Helper: options for clearCookie (must include domain to clear cross-subdomain cookies)
  const clearOpts = opts.cookieDomain
    ? { path: '/', domain: opts.cookieDomain }
    : { path: '/' };

  // Helper: unsign a cookie, return value or null
  function unsign(request: FastifyRequest, name: string): string | null {
    const raw = request.cookies[name];
    if (!raw) return null;
    const unsigned = request.unsignCookie(raw);
    if (!unsigned.valid || !unsigned.value) return null;
    return unsigned.value;
  }

  // Helper: keep the user's access token for /widget-token's subject_token,
  // with the fortium_user_id it was issued to (`sub`), taken from a validated
  // ID token. The cookie lives exactly as long as the token does.
  function setAccessTokenCookie(reply: FastifyReply, accessToken: string, expiresIn: number, sub: string) {
    reply.setCookie(ACCESS_TOKEN_COOKIE, serializeAccessToken(accessToken, expiresIn, sub), cookieOpts(expiresIn));
  }

  // Helper: concurrent refreshes of one refresh token within THIS process
  // share a single call. Refresh tokens rotate and Identity revokes the grant
  // when a used one comes back. The map is process-local: two instances
  // refreshing the same token still race, so an app running more than one
  // needs sticky sessions or accepts that risk. The primary mitigation is
  // refreshing only when the access token has expired (usableAccessToken).
  const refreshesInFlight = new Map<string, Promise<RefreshResult>>();
  function refreshOnce(refreshToken: string): Promise<RefreshResult> {
    let pending = refreshesInFlight.get(refreshToken);
    if (!pending) {
      pending = client.refreshToken(refreshToken).finally(() => refreshesInFlight.delete(refreshToken));
      refreshesInFlight.set(refreshToken, pending);
    }
    return pending;
  }

  // Helper: drop the tokens /widget-token proves the user with. Used when
  // they belong to someone other than the session user, or Identity refused them.
  function clearSubjectCookies(reply: FastifyReply) {
    reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
  }

  // Helper: refresh the widget subject server-side, and accept the result
  // only when its validated ID token names the session user. Returns the new
  // access token, or the error response for the route to send.
  async function refreshSubject(
    request: FastifyRequest,
    reply: FastifyReply,
    session: SessionPayload,
    audience: string,
  ): Promise<{ token: string } | { status: number; body: { error: string; error_description: string } }> {
    const refreshTokenValue = unsign(request, REFRESH_TOKEN_COOKIE);
    if (!refreshTokenValue) {
      return {
        status: 401,
        body: { error: 'unauthorized', error_description: 'no usable access token and no refresh token; re-authenticate' },
      };
    }

    let tokens: RefreshResult;
    try {
      tokens = await refreshOnce(refreshTokenValue);
    } catch (err) {
      const refreshErr = err as Error & { statusCode?: number };
      // Identity refused the refresh (4xx other than 429): the grant is gone,
      // so re-auth. 429, 5xx and network failures are retryable: 503.
      const status = refreshErr.statusCode;
      if (status && status >= 400 && status < 500 && status !== 429) {
        request.log.warn(
          { audience, subjectUserId: session.fortiumUserId, identityStatus: refreshErr.statusCode },
          'widget-token refresh refused by Identity',
        );
        return {
          status: 401,
          body: { error: 'unauthorized', error_description: 'access token refresh was refused; re-authenticate' },
        };
      }
      request.log.error(
        { audience, subjectUserId: session.fortiumUserId, identityStatus: status, err: refreshErr.message },
        'widget-token refresh failed (Identity unavailable)',
      );
      return {
        status: 503,
        body: { error: 'service_unavailable', error_description: 'identity provider is unavailable' },
      };
    }

    // The refresh token cookie is not tied to the session cookie: an app
    // route that sets only auth_token can leave an earlier user's in place.
    // Bind the result to the session user through its validated ID token.
    let refreshedUserId: string | undefined;
    let validationError: string | undefined;
    if (tokens.idToken) {
      try {
        refreshedUserId = (await client.validateIdToken(tokens.idToken)).fortium_user_id;
      } catch (err) {
        validationError = err instanceof Error ? err.message : String(err);
      }
    }
    if (!refreshedUserId || refreshedUserId !== session.fortiumUserId) {
      request.log.warn(
        {
          audience,
          subjectUserId: session.fortiumUserId,
          refreshedUserId,
          hasIdToken: !!tokens.idToken,
          err: validationError,
        },
        'widget-token refresh did not prove the session user',
      );
      clearSubjectCookies(reply);
      return {
        status: 401,
        body: { error: 'unauthorized', error_description: 'refreshed token does not belong to the session user; re-authenticate' },
      };
    }

    setAccessTokenCookie(reply, tokens.accessToken, tokens.expiresIn, refreshedUserId);
    if (tokens.refreshToken) {
      reply.setCookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, cookieOpts(7 * 86400));
    }
    return { token: tokens.accessToken };
  }

  // Helper: the login_hint for this /login, or undefined. A valid query
  // hint wins; resolveLoginHint is consulted only when the query carries no
  // valid one. The login never fails because of the hint, and its value is
  // never logged or reflected anywhere but the authorization URL.
  async function loginHintFor(request: FastifyRequest): Promise<string | undefined> {
    const rawHint = (request.query as Record<string, unknown>).login_hint;
    if (rawHint !== undefined) {
      const hint = sanitizeLoginHint(rawHint);
      if (hint) return hint;
      request.log.debug(
        {
          loginHintSource: 'query',
          loginHintType: typeof rawHint,
          loginHintLength: typeof rawHint === 'string' ? rawHint.length : undefined,
        },
        'OIDC login: login_hint rejected, dropped',
      );
    }
    if (!opts.resolveLoginHint) return undefined;

    let resolved: unknown;
    try {
      resolved = await opts.resolveLoginHint(request);
    } catch (err) {
      request.log.warn(
        { err: err instanceof Error ? err.message : String(err) },
        'OIDC login: resolveLoginHint threw, proceeding without a login_hint',
      );
      return undefined;
    }
    if (resolved === undefined) return undefined;
    const hint = sanitizeLoginHint(resolved);
    if (!hint) {
      request.log.debug(
        {
          loginHintSource: 'resolveLoginHint',
          loginHintType: typeof resolved,
          loginHintLength: typeof resolved === 'string' ? resolved.length : undefined,
        },
        'OIDC login: login_hint rejected, dropped',
      );
    }
    return hint;
  }

  // ------------------------------------------------------------------
  // GET /auth/login — Redirect to Identity for OIDC authentication
  // ------------------------------------------------------------------
  app.get('/login', async (request, reply) => {
    // Optional OIDC prompt and login_hint. Core forwards a prompt only when
    // it is allowed and a login_hint only when sanitizeLoginHint accepts it.
    const promptParam = (request.query as Record<string, unknown>).prompt;
    const loginHint = await loginHintFor(request);

    // Use the configured callbackUrl directly — deriving from request.hostname
    // breaks behind reverse proxies (e.g., nginx → Render internal hostname).
    const { url, state } = await client.generateAuthorizationUrl(opts.callbackUrl, {
      prompt: typeof promptParam === 'string' ? promptParam : undefined,
      loginHint,
    });

    // Optional per-request landing path. Only a validated relative path is
    // kept (see sanitizeReturnTo); anything else is dropped and /callback
    // falls back to postLoginPath. It rides on THIS attempt's pending state,
    // so overlapping logins each keep their own.
    const rawReturnTo = (request.query as Record<string, unknown>).returnTo;
    const returnTo = sanitizeReturnTo(rawReturnTo);
    if (returnTo) {
      state.returnTo = returnTo;
    } else if (rawReturnTo !== undefined) {
      request.log.debug(
        {
          returnToType: typeof rawReturnTo,
          returnToLength: typeof rawReturnTo === 'string' ? rawReturnTo.length : undefined,
        },
        'OIDC login: returnTo rejected, falling back to postLoginPath',
      );
    }

    // Append to the array of pending auth attempts so overlapping flows
    // (double-click, second tab) don't clobber each other's PKCE state.
    const existingStates = parsePendingStates(unsign(request, OIDC_STATE_COOKIE));
    const updatedStates = appendPendingState(existingStates, state);
    reply.setCookie(OIDC_STATE_COOKIE, serializePendingStates(updatedStates), cookieOpts(600));
    reply.redirect(url);
  });

  // ------------------------------------------------------------------
  // GET /auth/callback — Handle OIDC callback, exchange code, set cookies
  // ------------------------------------------------------------------
  app.get('/callback', async (request, reply) => {
    try {
      const { code, state } = request.query as { code?: string; state?: string };

      if (!code || !state) {
        return reply.redirect(`${opts.frontendUrl}/login?error=invalid_callback`);
      }

      // Validate OIDC state from cookie
      const rawCookie = request.cookies[OIDC_STATE_COOKIE];
      app.log.info(
        { hasCookie: !!rawCookie, cookieName: OIDC_STATE_COOKIE, allCookies: Object.keys(request.cookies) },
        'OIDC callback: checking state cookie'
      );
      const stateValue = unsign(request, OIDC_STATE_COOKIE);
      if (!stateValue) {
        app.log.warn(
          { rawCookiePresent: !!rawCookie, unsignResult: rawCookie ? 'invalid_signature' : 'no_cookie' },
          'OIDC callback: state_missing'
        );
        // Clear all auth cookies so the next login attempt starts clean (prevents loop)
        reply.clearCookie(OIDC_STATE_COOKIE, clearOpts);
        reply.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
        reply.clearCookie(ID_TOKEN_COOKIE, clearOpts);
        reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
        reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
        return reply.redirect(`${opts.frontendUrl}/login?error=state_missing`);
      }

      // Select the pending attempt whose state matches the returned param.
      // Overlapping flows store multiple attempts; consume only the matching one.
      const pendingStates = parsePendingStates(stateValue);
      const oidcState = selectPendingState(pendingStates, state);
      if (!oidcState) {
        reply.clearCookie(OIDC_STATE_COOKIE, clearOpts);
        return reply.redirect(`${opts.frontendUrl}/login?error=state_mismatch`);
      }

      // Remove the consumed attempt, leaving any other in-flight attempts intact.
      // Rewrite the cookie BEFORE the exchange (mirrors prior clear-before-exchange).
      const remainingStates = removePendingState(pendingStates, state);
      if (remainingStates.length === 0) {
        reply.clearCookie(OIDC_STATE_COOKIE, clearOpts);
      } else {
        reply.setCookie(OIDC_STATE_COOKIE, serializePendingStates(remainingStates), cookieOpts(600));
      }

      // Exchange code for tokens
      const { idToken, accessToken, expiresIn, refreshToken, claims } = await client.exchangeCode(code, oidcState);

      // Run authorize hook — apps check permissions, upsert records, etc.
      let extraSessionData: Record<string, unknown> = {};
      if (opts.authorize) {
        try {
          extraSessionData = await opts.authorize(claims);
        } catch (authError) {
          const reason = authError instanceof Error ? authError.message : 'not_authorized';
          const emailParam = claims.email ? `&email=${encodeURIComponent(claims.email)}` : '';
          return reply.redirect(`${opts.frontendUrl}/login?error=${encodeURIComponent(reason)}${emailParam}`);
        }
      }

      // Create session JWT
      const sessionPayload: SessionPayload = {
        fortiumUserId: claims.fortium_user_id,
        email: claims.email,
        ...extraSessionData,
      };
      const sessionToken = await createSessionToken(sessionPayload, sessionConfig);

      // Set cookies
      reply.setCookie(AUTH_TOKEN_COOKIE, sessionToken, cookieOpts(86400)); // 24h
      reply.setCookie(ID_TOKEN_COOKIE, idToken, cookieOpts(86400)); // 24h

      if (refreshToken) {
        reply.setCookie(REFRESH_TOKEN_COOKIE, refreshToken, cookieOpts(7 * 86400)); // 7d
      } else {
        // An earlier user's refresh token must not survive this login.
        reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
      }
      setAccessTokenCookie(reply, accessToken, expiresIn, claims.fortium_user_id);

      // Land on this attempt's returnTo (validated at /login, carried in the
      // signed state cookie) or the registration-time default.
      reply.redirect(oidcState.returnTo ? `${opts.frontendUrl}${oidcState.returnTo}` : postLoginRedirect);
    } catch (error) {
      app.log.error({ err: error, message: error instanceof Error ? error.message : String(error) }, 'OIDC callback failed');
      reply.redirect(`${opts.frontendUrl}/login?error=callback_failed`);
    }
  });

  // ------------------------------------------------------------------
  // GET /auth/me — Return current user from session
  // ------------------------------------------------------------------
  app.get('/me', async (request, reply) => {
    const token = unsign(request, AUTH_TOKEN_COOKIE);
    if (!token) {
      return reply.status(401).send({ error: { code: 'UNAUTHORIZED', message: 'Not authenticated' } });
    }

    const session = await verifySessionToken(token, sessionConfig);
    if (!session) {
      return reply.status(401).send({ error: { code: 'UNAUTHORIZED', message: 'Invalid session' } });
    }

    if (opts.getMe) {
      const result = await opts.getMe(session);
      return reply.send(result);
    }

    reply.send({ user: { fortiumUserId: session.fortiumUserId, email: session.email } });
  });

  // ------------------------------------------------------------------
  // POST /auth/refresh — Exchange refresh token for new tokens
  // ------------------------------------------------------------------
  app.post('/refresh', async (request, reply) => {
    const refreshTokenValue = unsign(request, REFRESH_TOKEN_COOKIE);
    if (!refreshTokenValue) {
      return reply.status(401).send({ error: { code: 'NO_REFRESH_TOKEN', message: 'No refresh token' } });
    }

    try {
      const tokens = await refreshOnce(refreshTokenValue);

      if (tokens.idToken) {
        const claims = await client.validateIdToken(tokens.idToken);

        // Rebuild session with authorize hook
        let extraSessionData: Record<string, unknown> = {};
        if (opts.authorize) {
          extraSessionData = await opts.authorize(claims);
        }

        const sessionPayload: SessionPayload = {
          fortiumUserId: claims.fortium_user_id,
          email: claims.email,
          ...extraSessionData,
        };
        const sessionToken = await createSessionToken(sessionPayload, sessionConfig);

        reply.setCookie(AUTH_TOKEN_COOKIE, sessionToken, cookieOpts(86400));
        reply.setCookie(ID_TOKEN_COOKIE, tokens.idToken, cookieOpts(86400));
        setAccessTokenCookie(reply, tokens.accessToken, tokens.expiresIn, claims.fortium_user_id);
      } else {
        // No ID token, so no proven user to bind the access token to.
        reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
      }

      if (tokens.refreshToken) {
        reply.setCookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, cookieOpts(7 * 86400));
      }

      reply.send({ success: true });
    } catch {
      // Clear all cookies on refresh failure
      reply.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
      reply.clearCookie(ID_TOKEN_COOKIE, clearOpts);
      reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
      reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
      return reply.status(401).send({ error: { code: 'REFRESH_FAILED', message: 'Token refresh failed' } });
    }
  });

  // ------------------------------------------------------------------
  // GET /auth/widget-token — Exchange user session for a narrow-audience JWT
  // ------------------------------------------------------------------
  // RFC 8693 Token Exchange consumer route. The user must be authenticated
  // (signed session cookie). The app's OIDC client_id must be allowlisted
  // on Identity for the requested `audience` (see Identity's migration 033
  // + 034 + docs/WIDGET_TOKEN_EXCHANGE.md).
  //
  // The subject_token is the user's own Identity access token (Identity
  // #63), read from its cookie. The cookie records the user the token was
  // issued to, and a token issued to anyone but the session user is refused
  // with 401 (#18). Only when that token is missing or expired does the route
  // refresh it server-side, writing back the rotated refresh token; with no
  // usable token after that it answers 401 so the frontend re-authenticates.
  // A token Identity refuses as invalid_grant (revoked before it expired) is
  // dropped and refreshed once.
  //
  // Returns a short-lived JWT (5-minute TTL) the frontend can hand to a
  // downstream service (e.g. the Ideas widget). The receiver validates
  // signature via Identity's JWKS and asserts aud === <its own hostname>.
  app.get<{ Querystring: { audience?: string } }>('/widget-token', async (request, reply) => {
    const start = Date.now();
    const audience = request.query.audience;

    if (!audience) {
      return reply.status(400).send({
        error: 'invalid_request',
        error_description: 'audience query parameter is required',
      });
    }

    // Session validation — same shape as /me
    const sessionToken = unsign(request, AUTH_TOKEN_COOKIE);
    if (!sessionToken) {
      return reply.status(401).send({
        error: 'unauthorized',
        error_description: 'authenticated session required',
      });
    }
    const session = await verifySessionToken(sessionToken, sessionConfig);
    if (!session) {
      return reply.status(401).send({
        error: 'unauthorized',
        error_description: 'invalid session',
      });
    }

    const stored = usableAccessToken(unsign(request, ACCESS_TOKEN_COOKIE));
    if (stored && stored.sub !== session.fortiumUserId) {
      request.log.warn(
        { audience, subjectUserId: session.fortiumUserId, storedUserId: stored.sub },
        'widget-token access token belongs to another user',
      );
      clearSubjectCookies(reply);
      return reply.status(401).send({
        error: 'unauthorized',
        error_description: 'stored access token does not belong to the session user; re-authenticate',
      });
    }

    let subjectToken = stored?.token;
    let subjectRefreshed = false;
    if (!subjectToken) {
      const refreshed = await refreshSubject(request, reply, session, audience);
      if (!('token' in refreshed)) return reply.status(refreshed.status).send(refreshed.body);
      subjectToken = refreshed.token;
      subjectRefreshed = true;
    }

    try {
      let tokenResponse: Awaited<ReturnType<IdentityClient['requestWidgetToken']>>;
      try {
        tokenResponse = await client.requestWidgetToken(subjectToken, audience);
      } catch (err) {
        // invalid_grant: Identity no longer accepts a token that has not
        // expired (its grant was revoked). Drop it and refresh once.
        if ((err as { oauthError?: string }).oauthError !== 'invalid_grant' || subjectRefreshed) throw err;
        const refreshed = await refreshSubject(request, reply, session, audience);
        if (!('token' in refreshed)) {
          reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
          return reply.status(refreshed.status).send(refreshed.body);
        }
        subjectToken = refreshed.token;
        subjectRefreshed = true;
        tokenResponse = await client.requestWidgetToken(subjectToken, audience);
      }
      const duration = Date.now() - start;
      request.log.info(
        {
          audience,
          subjectUserId: session.fortiumUserId,
          subjectRefreshed,
          durationMs: duration,
        },
        'widget-token exchange succeeded',
      );
      return reply.send({
        accessToken: tokenResponse.access_token,
        expiresIn: tokenResponse.expires_in,
        tokenType: tokenResponse.token_type,
        audience,
      });
    } catch (err) {
      const duration = Date.now() - start;
      const oauthErr = err as Error & { statusCode?: number; oauthError?: string };

      // invalid_grant on a token refreshed in this request: re-authenticate.
      if (oauthErr.oauthError === 'invalid_grant') {
        request.log.warn(
          { audience, subjectUserId: session.fortiumUserId, durationMs: duration, oauthError: oauthErr.oauthError },
          'widget-token exchange refused a freshly refreshed token',
        );
        reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
        return reply.status(401).send({
          error: 'unauthorized',
          error_description: 'access token was refused; re-authenticate',
        });
      }

      // Identity-returned 4xx — forward the OAuth error code verbatim
      if (oauthErr.statusCode && oauthErr.statusCode >= 400 && oauthErr.statusCode < 500) {
        request.log.warn(
          {
            audience,
            subjectUserId: session.fortiumUserId,
            durationMs: duration,
            identityStatus: oauthErr.statusCode,
            oauthError: oauthErr.oauthError,
          },
          'widget-token exchange refused by Identity',
        );
        return reply.status(oauthErr.statusCode).send({
          error: oauthErr.oauthError || 'invalid_request',
          error_description: oauthErr.message,
        });
      }

      // Identity 5xx, network failure, or timeout → 503
      request.log.error(
        {
          audience,
          subjectUserId: session.fortiumUserId,
          durationMs: duration,
          err: oauthErr.message,
        },
        'widget-token exchange failed (Identity unreachable)',
      );
      return reply.status(503).send({
        error: 'service_unavailable',
        error_description: 'identity provider is unavailable',
      });
    }
  });

  // ------------------------------------------------------------------
  // POST /auth/logout — Clear cookies, return Identity logout URL (for SPAs)
  // ------------------------------------------------------------------
  app.post('/logout', async (request, reply) => {
    const idToken = unsign(request, ID_TOKEN_COOKIE);

    reply.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(ID_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);

    const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
    reply.send({ success: true, logoutUrl });
  });

  // ------------------------------------------------------------------
  // GET /auth/logout — Clear cookies, redirect to Identity logout (for MPA/links)
  // ------------------------------------------------------------------
  app.get('/logout', async (request, reply) => {
    const idToken = unsign(request, ID_TOKEN_COOKIE);

    reply.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(ID_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);

    const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
    reply.redirect(logoutUrl);
  });

  // ------------------------------------------------------------------
  // GET /auth/switch-account — Clear cookies, destroy Identity session,
  // redirect back to app login with fresh account picker
  // ------------------------------------------------------------------
  app.get('/switch-account', async (_request, reply) => {
    reply.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(ID_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
    reply.clearCookie(OIDC_STATE_COOKIE, clearOpts);

    const identityBase = opts.issuer.replace(/\/oidc$/, '');
    const returnTo = `${opts.frontendUrl}/login?switch=1`;
    reply.redirect(
      `${identityBase}/auth/signout-and-retry?client_id=${encodeURIComponent(opts.clientId)}&return_to=${encodeURIComponent(returnTo)}`,
    );
  });
}

export const identityPlugin = fp(identityPluginImpl, {
  name: '@fortium/identity-client-fastify',
  dependencies: ['@fastify/cookie'],
});

// M2M type augmentation
declare module 'fastify' {
  interface FastifyRequest {
    m2m?: M2MTokenPayload;
  }
}

/**
 * Creates a Fastify preHandler that validates Identity-issued M2M (client_credentials) JWTs.
 * Use on API routes that accept system-to-system Bearer tokens.
 */
export function createM2MAuth(opts: M2MAuthOptions) {
  return async function m2mAuth(request: FastifyRequest, reply: FastifyReply) {
    const auth = request.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return reply.status(401).send({ error: 'Bearer token required' });
    }
    try {
      request.m2m = await verifyM2MToken(auth.slice(7), opts);
    } catch {
      return reply.status(401).send({ error: 'Invalid token' });
    }
  };
}
