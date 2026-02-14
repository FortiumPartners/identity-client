/**
 * Session JWT management.
 *
 * Creates and verifies HS256 session JWTs stored in signed httpOnly cookies.
 * Each app sets its own issuer (e.g., 'gateway', 'payouts').
 */

import { SignJWT, jwtVerify } from 'jose';
import type { SessionPayload } from './types.js';

export interface SessionConfig {
  jwtSecret: string;
  issuer: string;
  expiresIn?: string; // Default: '24h'
}

/**
 * Create a signed HS256 session JWT.
 * The payload always includes fortiumUserId and email, plus any extra data
 * returned by the authorize hook.
 */
export async function createSessionToken(
  payload: SessionPayload,
  config: SessionConfig
): Promise<string> {
  const secret = new TextEncoder().encode(config.jwtSecret);

  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(config.expiresIn || '24h')
    .setIssuer(config.issuer)
    .sign(secret);
}

/**
 * Verify a session JWT and return the payload, or null if invalid/expired.
 */
export async function verifySessionToken(
  token: string,
  config: SessionConfig
): Promise<SessionPayload | null> {
  try {
    const secret = new TextEncoder().encode(config.jwtSecret);
    const { payload } = await jwtVerify(token, secret, {
      issuer: config.issuer,
    });

    if (!payload.fortiumUserId || !payload.email) {
      return null;
    }

    return payload as unknown as SessionPayload;
  } catch {
    return null;
  }
}
