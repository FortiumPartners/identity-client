/**
 * The user's Identity access token, kept in a signed httpOnly cookie so the
 * widget-token route can present it as the RFC 8693 subject_token (Identity #63).
 *
 * Identity's user access tokens are opaque, so their expiry cannot be read
 * off the token. The cookie stores it alongside: {"t": token, "exp": epoch ms}.
 */
/** Treat the token as expired this long before it is, so the exchange never races its end. */
export declare const ACCESS_TOKEN_EXPIRY_SKEW_MS = 30000;
/** Serialize an access token and its lifetime (seconds, the token response's expires_in). */
export declare function serializeAccessToken(accessToken: string, expiresIn: number, now?: number): string;
/**
 * The stored access token if it is still usable, else null.
 *
 * Null is the only thing that should send a caller to a refresh. Refresh
 * tokens rotate and Identity revokes the whole grant when a used one comes
 * back, so refreshing while this still returns a token invites a race
 * between tabs that logs the user out.
 */
export declare function usableAccessToken(raw: string | null | undefined, now?: number): string | null;
