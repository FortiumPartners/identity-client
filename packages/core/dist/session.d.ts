/**
 * Session JWT management.
 *
 * Creates and verifies HS256 session JWTs stored in signed httpOnly cookies.
 * Each app sets its own issuer (e.g., 'gateway', 'payouts').
 */
import type { SessionPayload } from './types.js';
export interface SessionConfig {
    jwtSecret: string;
    issuer: string;
    expiresIn?: string;
}
/**
 * Create a signed HS256 session JWT.
 * The payload always includes fortiumUserId and email, plus any extra data
 * returned by the authorize hook.
 */
export declare function createSessionToken(payload: SessionPayload, config: SessionConfig): Promise<string>;
/**
 * Verify a session JWT and return the payload, or null if invalid/expired.
 */
export declare function verifySessionToken(token: string, config: SessionConfig): Promise<SessionPayload | null>;
