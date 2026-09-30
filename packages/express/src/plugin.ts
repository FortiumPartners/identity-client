/**
 * Express plugin for Fortium Identity OIDC authentication.
 *
 * Returns an Express Router with auth routes (/login, /callback, /me, etc.)
 * and enforces the standard OIDC flow with signed httpOnly cookies.
 *
 * Apps customize behavior via hooks (authorize, getMe) — not by
 * reimplementing the OIDC flow.
 */

import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
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
  /** Secret for signing session JWTs and cookies */
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
   * Called after Identity authenticates the user.
   * Use to check authorization (e.g., admin allowlist) and return extra session data.
   * Throw to reject the login. Return extra fields to include in the session JWT.
   */
  authorize?: (claims: FortiumClaims) => Promise<Record<string, unknown>>;

  /**
   * Called by GET /me to build the response from the session.
   * If not provided, returns { user: { fortiumUserId, email } }.
   */
  getMe?: (session: SessionPayload) => Promise<Record<string, unknown>>;

  /**
   * Called during callback after token exchange to extract extra cookie values.
   * Return a map of cookie name → value to set alongside standard auth cookies.
   * Useful for storing the raw access token for backend forwarding (e.g., Talent).
   */
  extraCookies?: (tokens: { accessToken: string; idToken: string; refreshToken?: string }, claims: FortiumClaims) => Record<string, { value: string; maxAge: number }>;

  /**
   * Called by GET /login when the query carries no valid `login_hint`, to
   * derive one server-side (e.g. from a signed cookie) instead of putting an
   * email address in a URL. The result is validated like the query parameter
   * and dropped when invalid. If it throws, the login proceeds without a hint.
   */
  resolveLoginHint?: (req: Request) => string | undefined | Promise<string | undefined>;
}

// Cookie name helpers
function cookieName(prefix: string, name: string): string {
  return prefix ? `${prefix}_${name}` : name;
}

export function createIdentityRouter(opts: IdentityPluginOptions): Router {
  const router = Router();
  const prefix = opts.cookiePrefix || '';
  const OIDC_STATE_COOKIE = cookieName(prefix, 'oidc_state');
  const AUTH_TOKEN_COOKIE = cookieName(prefix, 'auth_token');
  const ID_TOKEN_COOKIE = cookieName(prefix, 'id_token');
  const REFRESH_TOKEN_COOKIE = cookieName(prefix, 'refresh_token');
  // Distinct from the `access_token` apps set through extraCookies (Talent):
  // this one also records the token's expiry, which /widget-token needs.
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
  function cookieOpts(maxAge: number) {
    const base: Record<string, unknown> = {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax' as const,
      maxAge: maxAge * 1000, // Express uses milliseconds
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

  // Helper: read a signed cookie, return value or null
  function readSignedCookie(req: Request, name: string): string | null {
    const value = req.signedCookies?.[name];
    if (!value) return null;
    return value;
  }

  // Helper: keep the user's access token for /widget-token's subject_token,
  // with the fortium_user_id it was issued to (`sub`), taken from a validated
  // ID token. The cookie lives exactly as long as the token does.
  function setAccessTokenCookie(res: Response, accessToken: string, expiresIn: number, sub: string) {
    res.cookie(ACCESS_TOKEN_COOKIE, serializeAccessToken(accessToken, expiresIn, sub), cookieOpts(expiresIn));
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
  function clearSubjectCookies(res: Response) {
    res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
    res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
  }

  // Helper: refresh the widget subject server-side, and accept the result
  // only when its validated ID token names the session user. Returns the new
  // access token, or the error response for the route to send.
  async function refreshSubject(
    req: Request,
    res: Response,
    session: SessionPayload,
    audience: string,
  ): Promise<{ token: string } | { status: number; body: { error: string; error_description: string } }> {
    const refreshTokenValue = readSignedCookie(req, REFRESH_TOKEN_COOKIE);
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
        console.log(
          JSON.stringify({
            level: 'warn',
            msg: 'widget-token refresh refused by Identity',
            audience,
            subjectUserId: session.fortiumUserId,
            identityStatus: refreshErr.statusCode,
          }),
        );
        return {
          status: 401,
          body: { error: 'unauthorized', error_description: 'access token refresh was refused; re-authenticate' },
        };
      }
      console.log(
        JSON.stringify({
          level: 'error',
          msg: 'widget-token refresh failed (Identity unavailable)',
          audience,
          subjectUserId: session.fortiumUserId,
          identityStatus: status,
          err: refreshErr.message,
        }),
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
      console.log(
        JSON.stringify({
          level: 'warn',
          msg: 'widget-token refresh did not prove the session user',
          audience,
          subjectUserId: session.fortiumUserId,
          refreshedUserId,
          hasIdToken: !!tokens.idToken,
          err: validationError,
        }),
      );
      clearSubjectCookies(res);
      return {
        status: 401,
        body: { error: 'unauthorized', error_description: 'refreshed token does not belong to the session user; re-authenticate' },
      };
    }

    setAccessTokenCookie(res, tokens.accessToken, tokens.expiresIn, refreshedUserId);
    if (tokens.refreshToken) {
      res.cookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, cookieOpts(7 * 86400));
    }
    return { token: tokens.accessToken };
  }

  // Helper: the login_hint for this /login, or undefined. A valid query
  // hint wins; resolveLoginHint is consulted only when the query carries no
  // valid one. The login never fails because of the hint, and its value is
  // never logged or reflected anywhere but the authorization URL.
  async function loginHintFor(req: Request): Promise<string | undefined> {
    const rawHint: unknown = req.query.login_hint;
    if (rawHint !== undefined) {
      const hint = sanitizeLoginHint(rawHint);
      if (hint) return hint;
      console.debug(
        JSON.stringify({
          level: 'debug',
          msg: 'OIDC login: login_hint rejected, dropped',
          loginHintSource: 'query',
          loginHintType: typeof rawHint,
          loginHintLength: typeof rawHint === 'string' ? rawHint.length : undefined,
        }),
      );
    }
    if (!opts.resolveLoginHint) return undefined;

    let resolved: unknown;
    try {
      resolved = await opts.resolveLoginHint(req);
    } catch (err) {
      console.log(
        JSON.stringify({
          level: 'warn',
          msg: 'OIDC login: resolveLoginHint threw, proceeding without a login_hint',
          err: err instanceof Error ? err.message : String(err),
        }),
      );
      return undefined;
    }
    if (resolved === undefined) return undefined;
    const hint = sanitizeLoginHint(resolved);
    if (!hint) {
      console.debug(
        JSON.stringify({
          level: 'debug',
          msg: 'OIDC login: login_hint rejected, dropped',
          loginHintSource: 'resolveLoginHint',
          loginHintType: typeof resolved,
          loginHintLength: typeof resolved === 'string' ? resolved.length : undefined,
        }),
      );
    }
    return hint;
  }

  // ------------------------------------------------------------------
  // GET /login — Redirect to Identity for OIDC authentication
  // ------------------------------------------------------------------
  router.get('/login', async (req: Request, res: Response) => {
    try {
      // Optional OIDC prompt and login_hint. Core forwards a prompt only when
      // it is allowed and a login_hint only when sanitizeLoginHint accepts it.
      const promptParam = req.query.prompt;
      const loginHint = await loginHintFor(req);

      // Use the configured callbackUrl directly — deriving from req.hostname
      // breaks behind reverse proxies (e.g., nginx → Render internal hostname).
      const { url, state } = await client.generateAuthorizationUrl(opts.callbackUrl, {
        prompt: typeof promptParam === 'string' ? promptParam : undefined,
        loginHint,
      });

      // Append to the array of pending auth attempts so overlapping flows
      // (double-click, second tab) don't clobber each other's PKCE state.
      const existingStates = parsePendingStates(readSignedCookie(req, OIDC_STATE_COOKIE));
      const updatedStates = appendPendingState(existingStates, state);
      res.cookie(OIDC_STATE_COOKIE, serializePendingStates(updatedStates), cookieOpts(600));
      res.redirect(url);
    } catch (error) {
      console.error('Login redirect failed:', error);
      res.redirect(`${opts.frontendUrl}/login?error=login_failed`);
    }
  });

  // ------------------------------------------------------------------
  // GET /callback — Handle OIDC callback, exchange code, set cookies
  // ------------------------------------------------------------------
  router.get('/callback', async (req: Request, res: Response) => {
    try {
      const { code, state } = req.query as { code?: string; state?: string };

      if (!code || !state) {
        return res.redirect(`${opts.frontendUrl}/login?error=invalid_callback`);
      }

      // Validate OIDC state from cookie
      const stateValue = readSignedCookie(req, OIDC_STATE_COOKIE);
      if (!stateValue) {
        console.warn('OIDC callback: state cookie missing or invalid');
        // Clear all auth cookies so the next login attempt starts clean (prevents loop)
        res.clearCookie(OIDC_STATE_COOKIE, clearOpts);
        res.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
        res.clearCookie(ID_TOKEN_COOKIE, clearOpts);
        res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
        res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
        return res.redirect(`${opts.frontendUrl}/login?error=state_missing`);
      }

      // Select the pending attempt whose state matches the returned param.
      // Overlapping flows store multiple attempts; consume only the matching one.
      const pendingStates = parsePendingStates(stateValue);
      const oidcState = selectPendingState(pendingStates, state);
      if (!oidcState) {
        res.clearCookie(OIDC_STATE_COOKIE, clearOpts);
        return res.redirect(`${opts.frontendUrl}/login?error=state_mismatch`);
      }

      // Remove the consumed attempt, leaving any other in-flight attempts intact.
      // Rewrite the cookie BEFORE the exchange (mirrors prior clear-before-exchange).
      const remainingStates = removePendingState(pendingStates, state);
      if (remainingStates.length === 0) {
        res.clearCookie(OIDC_STATE_COOKIE, clearOpts);
      } else {
        res.cookie(OIDC_STATE_COOKIE, serializePendingStates(remainingStates), cookieOpts(600));
      }

      // Exchange code for tokens
      const tokenResult = await client.exchangeCode(code, oidcState);
      const { idToken, refreshToken, claims } = tokenResult;

      // Run authorize hook
      let extraSessionData: Record<string, unknown> = {};
      if (opts.authorize) {
        try {
          extraSessionData = await opts.authorize(claims);
        } catch (authError) {
          const reason = authError instanceof Error ? authError.message : 'not_authorized';
          const emailParam = claims.email ? `&email=${encodeURIComponent(claims.email)}` : '';
          return res.redirect(`${opts.frontendUrl}/login?error=${encodeURIComponent(reason)}${emailParam}`);
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
      res.cookie(AUTH_TOKEN_COOKIE, sessionToken, cookieOpts(86400)); // 24h
      res.cookie(ID_TOKEN_COOKIE, idToken, cookieOpts(86400)); // 24h

      if (refreshToken) {
        res.cookie(REFRESH_TOKEN_COOKIE, refreshToken, cookieOpts(7 * 86400)); // 7d
      } else {
        // An earlier user's refresh token must not survive this login.
        res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
      }
      setAccessTokenCookie(res, tokenResult.accessToken, tokenResult.expiresIn, claims.fortium_user_id);

      // Set extra cookies if hook provided (e.g., access_token for backend forwarding)
      if (opts.extraCookies) {
        const extras = opts.extraCookies(
          { accessToken: tokenResult.accessToken, idToken, refreshToken },
          claims,
        );
        for (const [name, { value, maxAge }] of Object.entries(extras)) {
          res.cookie(cookieName(prefix, name), value, cookieOpts(maxAge));
        }
      }

      res.redirect(postLoginRedirect);
    } catch (error) {
      console.error('OIDC callback failed:', error);
      res.redirect(`${opts.frontendUrl}/login?error=callback_failed`);
    }
  });

  // ------------------------------------------------------------------
  // GET /me — Return current user from session
  // ------------------------------------------------------------------
  router.get('/me', async (req: Request, res: Response) => {
    const token = readSignedCookie(req, AUTH_TOKEN_COOKIE);
    if (!token) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Not authenticated' } });
    }

    const session = await verifySessionToken(token, sessionConfig);
    if (!session) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid session' } });
    }

    if (opts.getMe) {
      const result = await opts.getMe(session);
      return res.json(result);
    }

    res.json({ user: { fortiumUserId: session.fortiumUserId, email: session.email } });
  });

  // ------------------------------------------------------------------
  // POST /refresh — Exchange refresh token for new tokens
  // ------------------------------------------------------------------
  router.post('/refresh', async (req: Request, res: Response) => {
    const refreshTokenValue = readSignedCookie(req, REFRESH_TOKEN_COOKIE);
    if (!refreshTokenValue) {
      return res.status(401).json({ error: { code: 'NO_REFRESH_TOKEN', message: 'No refresh token' } });
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

        res.cookie(AUTH_TOKEN_COOKIE, sessionToken, cookieOpts(86400));
        res.cookie(ID_TOKEN_COOKIE, tokens.idToken, cookieOpts(86400));
        setAccessTokenCookie(res, tokens.accessToken, tokens.expiresIn, claims.fortium_user_id);
      } else {
        // No ID token, so no proven user to bind the access token to.
        res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
      }

      if (tokens.refreshToken) {
        res.cookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, cookieOpts(7 * 86400));
      }

      // Set extra cookies on refresh too
      if (opts.extraCookies && tokens.idToken) {
        const extras = opts.extraCookies(
          { accessToken: tokens.accessToken, idToken: tokens.idToken, refreshToken: tokens.refreshToken },
          await client.validateIdToken(tokens.idToken),
        );
        for (const [name, { value, maxAge }] of Object.entries(extras)) {
          res.cookie(cookieName(prefix, name), value, cookieOpts(maxAge));
        }
      }

      res.json({ success: true });
    } catch {
      // Clear all cookies on refresh failure
      res.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
      res.clearCookie(ID_TOKEN_COOKIE, clearOpts);
      res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
      res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
      return res.status(401).json({ error: { code: 'REFRESH_FAILED', message: 'Token refresh failed' } });
    }
  });

  // ------------------------------------------------------------------
  // GET /widget-token — Exchange user session for a narrow-audience JWT
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
  router.get('/widget-token', async (req: Request, res: Response) => {
    const start = Date.now();
    const audience = typeof req.query.audience === 'string' ? req.query.audience : undefined;

    if (!audience) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'audience query parameter is required',
      });
    }

    // Session validation — same shape as /me
    const sessionToken = readSignedCookie(req, AUTH_TOKEN_COOKIE);
    if (!sessionToken) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'authenticated session required',
      });
    }
    const session = await verifySessionToken(sessionToken, sessionConfig);
    if (!session) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'invalid session',
      });
    }

    const stored = usableAccessToken(readSignedCookie(req, ACCESS_TOKEN_COOKIE));
    if (stored && stored.sub !== session.fortiumUserId) {
      console.log(
        JSON.stringify({
          level: 'warn',
          msg: 'widget-token access token belongs to another user',
          audience,
          subjectUserId: session.fortiumUserId,
          storedUserId: stored.sub,
        }),
      );
      clearSubjectCookies(res);
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'stored access token does not belong to the session user; re-authenticate',
      });
    }

    let subjectToken = stored?.token;
    let subjectRefreshed = false;
    if (!subjectToken) {
      const refreshed = await refreshSubject(req, res, session, audience);
      if (!('token' in refreshed)) return res.status(refreshed.status).json(refreshed.body);
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
        const refreshed = await refreshSubject(req, res, session, audience);
        if (!('token' in refreshed)) {
          res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
          return res.status(refreshed.status).json(refreshed.body);
        }
        subjectToken = refreshed.token;
        subjectRefreshed = true;
        tokenResponse = await client.requestWidgetToken(subjectToken, audience);
      }
      const duration = Date.now() - start;
      console.log(
        JSON.stringify({
          level: 'info',
          msg: 'widget-token exchange succeeded',
          audience,
          subjectUserId: session.fortiumUserId,
          subjectRefreshed,
          durationMs: duration,
        }),
      );
      return res.json({
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
        console.log(
          JSON.stringify({
            level: 'warn',
            msg: 'widget-token exchange refused a freshly refreshed token',
            audience,
            subjectUserId: session.fortiumUserId,
            durationMs: duration,
            oauthError: oauthErr.oauthError,
          }),
        );
        res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
        return res.status(401).json({
          error: 'unauthorized',
          error_description: 'access token was refused; re-authenticate',
        });
      }

      // Identity-returned 4xx — forward the OAuth error code verbatim
      if (oauthErr.statusCode && oauthErr.statusCode >= 400 && oauthErr.statusCode < 500) {
        console.log(
          JSON.stringify({
            level: 'warn',
            msg: 'widget-token exchange refused by Identity',
            audience,
            subjectUserId: session.fortiumUserId,
            durationMs: duration,
            identityStatus: oauthErr.statusCode,
            oauthError: oauthErr.oauthError,
          }),
        );
        return res.status(oauthErr.statusCode).json({
          error: oauthErr.oauthError || 'invalid_request',
          error_description: oauthErr.message,
        });
      }

      // Identity 5xx, network failure, or timeout → 503
      console.log(
        JSON.stringify({
          level: 'error',
          msg: 'widget-token exchange failed (Identity unreachable)',
          audience,
          subjectUserId: session.fortiumUserId,
          durationMs: duration,
          err: oauthErr.message,
        }),
      );
      return res.status(503).json({
        error: 'service_unavailable',
        error_description: 'identity provider is unavailable',
      });
    }
  });

  // ------------------------------------------------------------------
  // POST /logout — Clear cookies, return Identity logout URL (for SPAs)
  // ------------------------------------------------------------------
  router.post('/logout', (req: Request, res: Response) => {
    const idToken = readSignedCookie(req, ID_TOKEN_COOKIE);

    res.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
    res.clearCookie(ID_TOKEN_COOKIE, clearOpts);
    res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
    res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);

    const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
    res.json({ success: true, logoutUrl });
  });

  // ------------------------------------------------------------------
  // GET /logout — Clear cookies, redirect to Identity logout (for MPA/links)
  // ------------------------------------------------------------------
  router.get('/logout', (req: Request, res: Response) => {
    const idToken = readSignedCookie(req, ID_TOKEN_COOKIE);

    res.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
    res.clearCookie(ID_TOKEN_COOKIE, clearOpts);
    res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
    res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);

    const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
    res.redirect(logoutUrl);
  });

  // ------------------------------------------------------------------
  // GET /switch-account — Clear cookies, destroy Identity session,
  // redirect back to app login with fresh account picker
  // ------------------------------------------------------------------
  router.get('/switch-account', (_req: Request, res: Response) => {
    res.clearCookie(AUTH_TOKEN_COOKIE, clearOpts);
    res.clearCookie(ID_TOKEN_COOKIE, clearOpts);
    res.clearCookie(REFRESH_TOKEN_COOKIE, clearOpts);
    res.clearCookie(ACCESS_TOKEN_COOKIE, clearOpts);
    res.clearCookie(OIDC_STATE_COOKIE, clearOpts);

    const identityBase = opts.issuer.replace(/\/oidc$/, '');
    const returnTo = `${opts.frontendUrl}/login?switch=1`;
    res.redirect(
      `${identityBase}/auth/signout-and-retry?client_id=${encodeURIComponent(opts.clientId)}&return_to=${encodeURIComponent(returnTo)}`,
    );
  });

  return router;
}

// M2M type augmentation
declare global {
  namespace Express {
    interface Request {
      m2m?: M2MTokenPayload;
    }
  }
}

/**
 * Creates Express middleware that validates Identity-issued M2M (client_credentials) JWTs.
 * Use on API routes that accept system-to-system Bearer tokens.
 */
export function createM2MAuth(opts: M2MAuthOptions) {
  return async function m2mAuth(req: Request, res: Response, next: NextFunction) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Bearer token required' });
    }
    try {
      req.m2m = await verifyM2MToken(auth.slice(7), opts);
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}
