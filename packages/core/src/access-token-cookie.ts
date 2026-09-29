/**
 * The user's Identity access token, kept in a signed httpOnly cookie so the
 * widget-token route can present it as the RFC 8693 subject_token (Identity #63).
 *
 * Identity's user access tokens are opaque, so their expiry cannot be read
 * off the token. The cookie stores it alongside: {"t": token, "exp": epoch ms}.
 */

/** Treat the token as expired this long before it is, so the exchange never races its end. */
export const ACCESS_TOKEN_EXPIRY_SKEW_MS = 30_000;

/** Serialize an access token and its lifetime (seconds, the token response's expires_in). */
export function serializeAccessToken(accessToken: string, expiresIn: number, now = Date.now()): string {
  return JSON.stringify({ t: accessToken, exp: now + expiresIn * 1000 });
}

/**
 * The stored access token if it is still usable, else null.
 *
 * Null is the only thing that should send a caller to a refresh. Refresh
 * tokens rotate and Identity revokes the whole grant when a used one comes
 * back, so refreshing while this still returns a token invites a race
 * between tabs that logs the user out.
 */
export function usableAccessToken(raw: string | null | undefined, now = Date.now()): string | null {
  if (!raw) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  const { t, exp } = (parsed ?? {}) as { t?: unknown; exp?: unknown };
  if (typeof t !== 'string' || !t || typeof exp !== 'number') return null;
  if (exp - ACCESS_TOKEN_EXPIRY_SKEW_MS <= now) return null;
  return t;
}
