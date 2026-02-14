/**
 * Fastify plugin for Fortium Identity OIDC authentication.
 *
 * Registers auth routes (/auth/login, /auth/callback, /auth/me, etc.)
 * and enforces the standard OIDC flow with signed httpOnly cookies.
 *
 * Apps customize behavior via hooks (authorize, getMe) — not by
 * reimplementing the OIDC flow.
 */
import type { FastifyInstance } from 'fastify';
import '@fastify/cookie';
import type { FortiumClaims, SessionPayload } from '@fortium/identity-client';
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
export {};
