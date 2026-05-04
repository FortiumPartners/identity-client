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
import '@fastify/cookie';
import type { FortiumClaims, SessionPayload, M2MAuthOptions, M2MTokenPayload } from '@fortium/identity-client';
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
}
declare function identityPluginImpl(app: FastifyInstance, opts: IdentityPluginOptions): Promise<void>;
export declare const identityPlugin: typeof identityPluginImpl;
declare module 'fastify' {
    interface FastifyRequest {
        m2m?: M2MTokenPayload;
    }
}
/**
 * Creates a Fastify preHandler that validates Identity-issued M2M (client_credentials) JWTs.
 * Use on API routes that accept system-to-system Bearer tokens.
 */
export declare function createM2MAuth(opts: M2MAuthOptions): (request: FastifyRequest, reply: FastifyReply) => Promise<undefined>;
export {};
