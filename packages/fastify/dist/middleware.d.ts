/**
 * requireAuth() preHandler for Fastify routes.
 *
 * Validates the session JWT from the auth_token cookie (or Authorization header)
 * and attaches the session to request.user.
 *
 * Usage:
 *   import { requireAuth } from '@fortium/identity-client-fastify';
 *
 *   const auth = requireAuth({ jwtSecret: config.JWT_SECRET, issuer: 'gateway' });
 *   app.get('/api/protected', { preHandler: [auth] }, handler);
 */
import type { FastifyRequest, FastifyReply } from 'fastify';
import type { SessionPayload } from '@fortium/identity-client';
export interface RequireAuthOptions {
    jwtSecret: string;
    issuer: string;
    /** Cookie name for auth token (default: 'auth_token') */
    cookieName?: string;
}
declare module 'fastify' {
    interface FastifyRequest {
        user?: SessionPayload;
    }
}
/**
 * Creates a Fastify preHandler that validates the session JWT.
 * Checks signed cookie first, then Authorization: Bearer header.
 */
export declare function requireAuth(opts: RequireAuthOptions): (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
