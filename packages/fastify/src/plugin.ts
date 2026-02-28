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
} from '@fortium/identity-client';
import type { FortiumClaims, OIDCState, SessionPayload, M2MAuthOptions, M2MTokenPayload } from '@fortium/identity-client';

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

  // ------------------------------------------------------------------
  // GET /auth/login — Redirect to Identity for OIDC authentication
  // ------------------------------------------------------------------
  app.get('/login', async (request, reply) => {
    // Use the configured callbackUrl directly — deriving from request.hostname
    // breaks behind reverse proxies (e.g., nginx → Render internal hostname).
    const { url, state } = await client.generateAuthorizationUrl(opts.callbackUrl);

    // Append optional OIDC prompt parameter if provided and valid
    const ALLOWED_PROMPTS = ['login', 'select_account', 'consent', 'none'];
    const promptParam = (request.query as Record<string, string>).prompt;
    let redirectUrl = url;
    if (promptParam && ALLOWED_PROMPTS.includes(promptParam)) {
      const parsed = new URL(url);
      parsed.searchParams.set('prompt', promptParam);
      redirectUrl = parsed.toString();
    }

    reply.setCookie(OIDC_STATE_COOKIE, JSON.stringify(state), cookieOpts(600));
    reply.redirect(redirectUrl);
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
        return reply.redirect(`${opts.frontendUrl}/login?error=state_missing`);
      }

      const oidcState: OIDCState = JSON.parse(stateValue);
      if (state !== oidcState.state) {
        reply.clearCookie(OIDC_STATE_COOKIE, clearOpts);
        return reply.redirect(`${opts.frontendUrl}/login?error=state_mismatch`);
      }

      reply.clearCookie(OIDC_STATE_COOKIE, clearOpts);

      // Exchange code for tokens
      const { idToken, refreshToken, claims } = await client.exchangeCode(code, oidcState);

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
      }

      reply.redirect(postLoginRedirect);
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
      const tokens = await client.refreshToken(refreshTokenValue);

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
      return reply.status(401).send({ error: { code: 'REFRESH_FAILED', message: 'Token refresh failed' } });
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
