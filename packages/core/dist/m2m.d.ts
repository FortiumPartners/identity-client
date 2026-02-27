/**
 * M2M (Machine-to-Machine) token verification.
 *
 * Validates Identity-issued client_credentials JWTs using the public JWKS.
 * No client secret needed — only the issuer's public keys.
 */
import type { M2MTokenPayload, M2MAuthOptions } from './types.js';
export declare function verifyM2MToken(token: string, opts: M2MAuthOptions): Promise<M2MTokenPayload>;
