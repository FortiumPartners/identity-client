/**
 * Fastify plugin for Fortium Identity OIDC authentication.
 *
 * Registers auth routes (/auth/login, /auth/callback, /auth/me, etc.)
 * and enforces the standard OIDC flow with signed httpOnly cookies.
 *
 * Apps customize behavior via hooks (authorize, getMe) — not by
 * reimplementing the OIDC flow.
 */
import fp from 'fastify-plugin';
import '@fastify/cookie'; // Type augmentations for cookies
import { IdentityClient, createSessionToken, verifySessionToken, } from '@fortium/identity-client';
// Cookie name helpers
function cookieName(prefix, name) {
    return prefix ? `${prefix}_${name}` : name;
}
async function identityPluginImpl(app, opts) {
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
    function cookieOpts(maxAge) {
        return {
            httpOnly: true,
            secure: isProd,
            sameSite: 'lax',
            maxAge,
            path: '/',
            signed: true,
        };
    }
    // Helper: unsign a cookie, return value or null
    function unsign(request, name) {
        const raw = request.cookies[name];
        if (!raw)
            return null;
        const unsigned = request.unsignCookie(raw);
        if (!unsigned.valid || !unsigned.value)
            return null;
        return unsigned.value;
    }
    // ------------------------------------------------------------------
    // GET /auth/login — Redirect to Identity for OIDC authentication
    // ------------------------------------------------------------------
    app.get('/login', async (_request, reply) => {
        const { url, state } = await client.generateAuthorizationUrl(opts.callbackUrl);
        reply.setCookie(OIDC_STATE_COOKIE, JSON.stringify(state), cookieOpts(600));
        reply.redirect(url);
    });
    // ------------------------------------------------------------------
    // GET /auth/callback — Handle OIDC callback, exchange code, set cookies
    // ------------------------------------------------------------------
    app.get('/callback', async (request, reply) => {
        try {
            const { code, state } = request.query;
            if (!code || !state) {
                return reply.redirect(`${opts.frontendUrl}/login?error=invalid_callback`);
            }
            // Validate OIDC state from cookie
            const rawCookie = request.cookies[OIDC_STATE_COOKIE];
            app.log.info({ hasCookie: !!rawCookie, cookieName: OIDC_STATE_COOKIE, allCookies: Object.keys(request.cookies) }, 'OIDC callback: checking state cookie');
            const stateValue = unsign(request, OIDC_STATE_COOKIE);
            if (!stateValue) {
                app.log.warn({ rawCookiePresent: !!rawCookie, unsignResult: rawCookie ? 'invalid_signature' : 'no_cookie' }, 'OIDC callback: state_missing');
                return reply.redirect(`${opts.frontendUrl}/login?error=state_missing`);
            }
            const oidcState = JSON.parse(stateValue);
            if (state !== oidcState.state) {
                return reply.redirect(`${opts.frontendUrl}/login?error=state_mismatch`);
            }
            reply.clearCookie(OIDC_STATE_COOKIE, { path: '/' });
            // Exchange code for tokens
            const { idToken, refreshToken, claims } = await client.exchangeCode(code, oidcState);
            // Run authorize hook — apps check permissions, upsert records, etc.
            let extraSessionData = {};
            if (opts.authorize) {
                try {
                    extraSessionData = await opts.authorize(claims);
                }
                catch (authError) {
                    const reason = authError instanceof Error ? authError.message : 'not_authorized';
                    return reply.redirect(`${opts.frontendUrl}/login?error=${encodeURIComponent(reason)}`);
                }
            }
            // Create session JWT
            const sessionPayload = {
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
        }
        catch (error) {
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
                let extraSessionData = {};
                if (opts.authorize) {
                    extraSessionData = await opts.authorize(claims);
                }
                const sessionPayload = {
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
        }
        catch {
            // Clear all cookies on refresh failure
            reply.clearCookie(AUTH_TOKEN_COOKIE, { path: '/' });
            reply.clearCookie(ID_TOKEN_COOKIE, { path: '/' });
            reply.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
            return reply.status(401).send({ error: { code: 'REFRESH_FAILED', message: 'Token refresh failed' } });
        }
    });
    // ------------------------------------------------------------------
    // POST /auth/logout — Clear cookies, return Identity logout URL (for SPAs)
    // ------------------------------------------------------------------
    app.post('/logout', async (request, reply) => {
        const idToken = unsign(request, ID_TOKEN_COOKIE);
        reply.clearCookie(AUTH_TOKEN_COOKIE, { path: '/' });
        reply.clearCookie(ID_TOKEN_COOKIE, { path: '/' });
        reply.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
        const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
        reply.send({ success: true, logoutUrl });
    });
    // ------------------------------------------------------------------
    // GET /auth/logout — Clear cookies, redirect to Identity logout (for MPA/links)
    // ------------------------------------------------------------------
    app.get('/logout', async (request, reply) => {
        const idToken = unsign(request, ID_TOKEN_COOKIE);
        reply.clearCookie(AUTH_TOKEN_COOKIE, { path: '/' });
        reply.clearCookie(ID_TOKEN_COOKIE, { path: '/' });
        reply.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
        const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
        reply.redirect(logoutUrl);
    });
}
export const identityPlugin = fp(identityPluginImpl, {
    name: '@fortium/identity-client-fastify',
    dependencies: ['@fastify/cookie'],
});
