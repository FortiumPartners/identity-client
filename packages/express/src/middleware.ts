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
import { verifySessionToken } from '@fortium/identity-client';
import type { SessionPayload, SessionConfig } from '@fortium/identity-client';

export interface RequireAuthOptions {
  jwtSecret: string;
  issuer: string;
  /** Cookie name for auth token (default: 'auth_token') */
  cookieName?: string;
}

// Extend Express Request to include user
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
export function requireAuth(opts: RequireAuthOptions) {
  const sessionConfig: SessionConfig = {
    jwtSecret: opts.jwtSecret,
    issuer: opts.issuer,
  };
  const cookie = opts.cookieName || 'auth_token';

  return async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
    let token: string | undefined;

    // Try Authorization header first
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    }

    // Fall back to signed cookie
    if (!token && req.signedCookies?.[cookie]) {
      token = req.signedCookies[cookie];
    }

    if (!token) {
      res.status(401).json({
        error: { code: 'AUTH_MISSING_TOKEN', message: 'Authentication token is required' },
      });
      return;
    }

    const session = await verifySessionToken(token, sessionConfig);
    if (!session) {
      res.status(401).json({
        error: { code: 'AUTH_INVALID_TOKEN', message: 'Invalid or expired token' },
      });
      return;
    }

    req.user = session;
    next();
  };
}
