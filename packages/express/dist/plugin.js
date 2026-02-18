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
import { IdentityClient, createSessionToken, verifySessionToken, } from '@fortium/identity-client';
// Cookie name helpers
function cookieName(prefix, name) {
    return prefix ? `${prefix}_${name}` : name;
}
export function createIdentityRouter(opts) {
    const router = Router();
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
            maxAge: maxAge * 1000, // Express uses milliseconds
            path: '/',
            signed: true,
        };
    }
    // Helper: read a signed cookie, return value or null
    function readSignedCookie(req, name) {
        const value = req.signedCookies?.[name];
        if (!value)
            return null;
        return value;
    }
    // ------------------------------------------------------------------
    // GET /login — Redirect to Identity for OIDC authentication
    // ------------------------------------------------------------------
    router.get('/login', async (req, res) => {
        try {
            const callbackPath = new URL(opts.callbackUrl).pathname;
            const proto = req.headers['x-forwarded-proto'] || (isProd ? 'https' : 'http');
            const callbackUrl = `${proto}://${req.hostname}${callbackPath}`;
            const { url, state } = await client.generateAuthorizationUrl(callbackUrl);
            // Append optional OIDC prompt parameter if provided and valid
            const ALLOWED_PROMPTS = ['login', 'select_account', 'consent', 'none'];
            const promptParam = req.query.prompt;
            let redirectUrl = url;
            if (promptParam && ALLOWED_PROMPTS.includes(promptParam)) {
                const parsed = new URL(url);
                parsed.searchParams.set('prompt', promptParam);
                redirectUrl = parsed.toString();
            }
            res.cookie(OIDC_STATE_COOKIE, JSON.stringify(state), cookieOpts(600));
            res.redirect(redirectUrl);
        }
        catch (error) {
            console.error('Login redirect failed:', error);
            res.redirect(`${opts.frontendUrl}/login?error=login_failed`);
        }
    });
    // ------------------------------------------------------------------
    // GET /callback — Handle OIDC callback, exchange code, set cookies
    // ------------------------------------------------------------------
    router.get('/callback', async (req, res) => {
        try {
            const { code, state } = req.query;
            if (!code || !state) {
                return res.redirect(`${opts.frontendUrl}/login?error=invalid_callback`);
            }
            // Validate OIDC state from cookie
            const stateValue = readSignedCookie(req, OIDC_STATE_COOKIE);
            if (!stateValue) {
                console.warn('OIDC callback: state cookie missing or invalid');
                return res.redirect(`${opts.frontendUrl}/login?error=state_missing`);
            }
            const oidcState = JSON.parse(stateValue);
            if (state !== oidcState.state) {
                return res.redirect(`${opts.frontendUrl}/login?error=state_mismatch`);
            }
            res.clearCookie(OIDC_STATE_COOKIE, { path: '/' });
            // Exchange code for tokens
            const tokenResult = await client.exchangeCode(code, oidcState);
            const { idToken, refreshToken, claims } = tokenResult;
            // Run authorize hook
            let extraSessionData = {};
            if (opts.authorize) {
                try {
                    extraSessionData = await opts.authorize(claims);
                }
                catch (authError) {
                    const reason = authError instanceof Error ? authError.message : 'not_authorized';
                    return res.redirect(`${opts.frontendUrl}/login?error=${encodeURIComponent(reason)}`);
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
            res.cookie(AUTH_TOKEN_COOKIE, sessionToken, cookieOpts(86400)); // 24h
            res.cookie(ID_TOKEN_COOKIE, idToken, cookieOpts(86400)); // 24h
            if (refreshToken) {
                res.cookie(REFRESH_TOKEN_COOKIE, refreshToken, cookieOpts(7 * 86400)); // 7d
            }
            // Set extra cookies if hook provided (e.g., access_token for backend forwarding)
            if (opts.extraCookies) {
                const extras = opts.extraCookies({ accessToken: tokenResult.accessToken, idToken, refreshToken }, claims);
                for (const [name, { value, maxAge }] of Object.entries(extras)) {
                    res.cookie(cookieName(prefix, name), value, cookieOpts(maxAge));
                }
            }
            res.redirect(postLoginRedirect);
        }
        catch (error) {
            console.error('OIDC callback failed:', error);
            res.redirect(`${opts.frontendUrl}/login?error=callback_failed`);
        }
    });
    // ------------------------------------------------------------------
    // GET /me — Return current user from session
    // ------------------------------------------------------------------
    router.get('/me', async (req, res) => {
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
    router.post('/refresh', async (req, res) => {
        const refreshTokenValue = readSignedCookie(req, REFRESH_TOKEN_COOKIE);
        if (!refreshTokenValue) {
            return res.status(401).json({ error: { code: 'NO_REFRESH_TOKEN', message: 'No refresh token' } });
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
                res.cookie(AUTH_TOKEN_COOKIE, sessionToken, cookieOpts(86400));
                res.cookie(ID_TOKEN_COOKIE, tokens.idToken, cookieOpts(86400));
            }
            if (tokens.refreshToken) {
                res.cookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, cookieOpts(7 * 86400));
            }
            // Set extra cookies on refresh too
            if (opts.extraCookies && tokens.idToken) {
                const extras = opts.extraCookies({ accessToken: tokens.accessToken, idToken: tokens.idToken, refreshToken: tokens.refreshToken }, await client.validateIdToken(tokens.idToken));
                for (const [name, { value, maxAge }] of Object.entries(extras)) {
                    res.cookie(cookieName(prefix, name), value, cookieOpts(maxAge));
                }
            }
            res.json({ success: true });
        }
        catch {
            // Clear all cookies on refresh failure
            res.clearCookie(AUTH_TOKEN_COOKIE, { path: '/' });
            res.clearCookie(ID_TOKEN_COOKIE, { path: '/' });
            res.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
            return res.status(401).json({ error: { code: 'REFRESH_FAILED', message: 'Token refresh failed' } });
        }
    });
    // ------------------------------------------------------------------
    // POST /logout — Clear cookies, return Identity logout URL (for SPAs)
    // ------------------------------------------------------------------
    router.post('/logout', (req, res) => {
        const idToken = readSignedCookie(req, ID_TOKEN_COOKIE);
        res.clearCookie(AUTH_TOKEN_COOKIE, { path: '/' });
        res.clearCookie(ID_TOKEN_COOKIE, { path: '/' });
        res.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
        const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
        res.json({ success: true, logoutUrl });
    });
    // ------------------------------------------------------------------
    // GET /logout — Clear cookies, redirect to Identity logout (for MPA/links)
    // ------------------------------------------------------------------
    router.get('/logout', (req, res) => {
        const idToken = readSignedCookie(req, ID_TOKEN_COOKIE);
        res.clearCookie(AUTH_TOKEN_COOKIE, { path: '/' });
        res.clearCookie(ID_TOKEN_COOKIE, { path: '/' });
        res.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
        const logoutUrl = client.getLogoutUrl(idToken || undefined, postLogoutRedirect);
        res.redirect(logoutUrl);
    });
    return router;
}
