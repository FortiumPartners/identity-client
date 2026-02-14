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
import { verifySessionToken } from '@fortium/identity-client';
/**
 * Creates a Fastify preHandler that validates the session JWT.
 * Checks signed cookie first, then Authorization: Bearer header.
 */
export function requireAuth(opts) {
    const sessionConfig = {
        jwtSecret: opts.jwtSecret,
        issuer: opts.issuer,
    };
    const cookie = opts.cookieName || 'auth_token';
    return async function authenticate(request, reply) {
        let token;
        // Try Authorization header first
        const authHeader = request.headers.authorization;
        if (authHeader?.startsWith('Bearer ')) {
            token = authHeader.slice(7);
        }
        // Fall back to signed cookie
        if (!token && request.cookies?.[cookie]) {
            const unsigned = request.unsignCookie(request.cookies[cookie]);
            if (unsigned.valid && unsigned.value) {
                token = unsigned.value;
            }
        }
        if (!token) {
            reply.status(401).send({
                error: { code: 'AUTH_MISSING_TOKEN', message: 'Authentication token is required' },
            });
            return;
        }
        const session = await verifySessionToken(token, sessionConfig);
        if (!session) {
            reply.status(401).send({
                error: { code: 'AUTH_INVALID_TOKEN', message: 'Invalid or expired token' },
            });
            return;
        }
        request.user = session;
    };
}
