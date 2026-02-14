/**
 * Session JWT management.
 *
 * Creates and verifies HS256 session JWTs stored in signed httpOnly cookies.
 * Each app sets its own issuer (e.g., 'gateway', 'payouts').
 */
import { SignJWT, jwtVerify } from 'jose';
/**
 * Create a signed HS256 session JWT.
 * The payload always includes fortiumUserId and email, plus any extra data
 * returned by the authorize hook.
 */
export async function createSessionToken(payload, config) {
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
export async function verifySessionToken(token, config) {
    try {
        const secret = new TextEncoder().encode(config.jwtSecret);
        const { payload } = await jwtVerify(token, secret, {
            issuer: config.issuer,
        });
        if (!payload.fortiumUserId || !payload.email) {
            return null;
        }
        return payload;
    }
    catch {
        return null;
    }
}
