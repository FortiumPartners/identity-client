/**
 * The user's Identity access token, kept in a signed httpOnly cookie so the
 * widget-token route can present it as the RFC 8693 subject_token (Identity #63).
 *
 * Identity's user access tokens are opaque, so neither their expiry nor their
 * user can be read off the token. The cookie stores both alongside:
 * {"t": token, "exp": epoch ms, "sub": fortium_user_id}. The route compares
 * `sub` with the session user before using the token (#18).
 */
/** Treat the token as expired this long before it is, so the exchange never races its end. */
export declare const ACCESS_TOKEN_EXPIRY_SKEW_MS = 30000;
/** A stored access token that is still usable, and the user it was issued to. */
export interface StoredAccessToken {
    token: string;
    sub: string;
}
/**
 * Serialize an access token, its lifetime (seconds, the token response's
 * expires_in) and the fortium_user_id of the user it was issued to.
 */
export declare function serializeAccessToken(accessToken: string, expiresIn: number, sub: string, now?: number): string;
/**
 * The stored access token and its user if the token is still usable, else null.
 *
 * Null is the only thing that should send a caller to a refresh. Refresh
 * tokens rotate and Identity revokes the whole grant when a used one comes
 * back, so refreshing while this still returns a token invites a race
 * between tabs that logs the user out.
 *
 * A cookie without `sub` (written by 1.4.0) is null: its user is unknown, so
 * it is never trusted and the caller refreshes, which proves the user again.
 */
export declare function usableAccessToken(raw: string | null | undefined, now?: number): StoredAccessToken | null;
