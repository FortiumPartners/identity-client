/**
 * requireAuth() middleware for Express routes.
 *
 * Validates the session JWT from the auth_token cookie (or Authorization header)
 * and attaches the session to req.user.
 *
 * Usage:
 *   import { requireAuth } from '@fortium/identity-client/express';
 *
 *   const auth = requireAuth({ jwtSecret: config.JWT_SECRET, issuer: 'ideas' });
 *   app.get('/api/protected', auth, handler);
 */
import type { Request, Response, NextFunction } from 'express';
import type { SessionPayload } from '@fortium/identity-client';
export interface RequireAuthOptions {
    jwtSecret: string;
    issuer: string;
    /** Cookie name for auth token (default: 'auth_token') */
    cookieName?: string;
}
declare global {
    namespace Express {
        interface Request {
            user?: SessionPayload;
        }
    }
}
/**
 * Creates Express middleware that validates the session JWT.
 * Checks Authorization: Bearer header first, then signed cookie.
 */
export declare function requireAuth(opts: RequireAuthOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
