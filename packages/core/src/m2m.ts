/**
 * M2M (Machine-to-Machine) token verification.
 *
 * Validates Identity-issued client_credentials JWTs using the public JWKS.
 * No client secret needed — only the issuer's public keys.
 */

import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { M2MTokenPayload, M2MAuthOptions } from './types.js';

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export async function verifyM2MToken(
  token: string,
  opts: M2MAuthOptions,
): Promise<M2MTokenPayload> {
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
    const tokenScopes = ((payload.scope as string) || '').split(' ');
    for (const s of opts.requiredScopes) {
      if (!tokenScopes.includes(s)) throw new Error(`Missing scope: ${s}`);
    }
  }

  return payload as M2MTokenPayload;
}
