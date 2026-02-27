/**
 * M2M (Machine-to-Machine) token verification.
 *
 * Validates Identity-issued client_credentials JWTs using the public JWKS.
 * No client secret needed — only the issuer's public keys.
 */
import { createRemoteJWKSet, jwtVerify } from 'jose';
const jwksCache = new Map();
export async function verifyM2MToken(token, opts) {
    let jwks = jwksCache.get(opts.issuer);
    if (!jwks) {
        jwks = createRemoteJWKSet(new URL('/.well-known/jwks.json', opts.issuer));
        jwksCache.set(opts.issuer, jwks);
    }
    const { payload } = await jwtVerify(token, jwks, {
        issuer: opts.issuer,
        ...(opts.audience && { audience: opts.audience }),
    });
    if (opts.requiredScopes?.length) {
        const tokenScopes = (payload.scope || '').split(' ');
        for (const s of opts.requiredScopes) {
            if (!tokenScopes.includes(s))
                throw new Error(`Missing scope: ${s}`);
        }
    }
    return payload;
}
