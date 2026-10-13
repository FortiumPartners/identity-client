/**
 * Login guard shared by both plugins: after a callback ends in an error, /login
 * refuses to start another authorization request for a short window.
 *
 * Without it, an app whose /login restarts the flow on an error loops between
 * the app and Identity until the browser gives up. The guard lives in its own
 * short-lived signed cookie, not in the oidc_state flow cookie: that cookie may
 * be gone (it lives 10 minutes, and an invalid_callback has no matching attempt
 * to consume). Pure helpers, no I/O: the caller owns cookie read and write.
 */
/** How long, in seconds, a failed callback blocks the next /login by default. */
export declare const LOGIN_GUARD_DEFAULT_SECONDS = 30;
/**
 * Cookie value recording that the last attempt ended in `error` at `now`.
 * The error goes through sanitizeCallbackError, so an attacker-controlled
 * `?error=` can only ever store a registered code or invalid_callback.
 */
export declare function serializeLoginGuard(error: unknown, now?: number): string;
/**
 * The error code to send the browser to while the guard is fresh, or undefined
 * when there is no guard, it is malformed, or `windowSeconds` have passed since
 * it was set. The age is checked here as well as through the cookie's maxAge,
 * because a browser's clock decides when a cookie expires and the server's must
 * decide when the guard does. Never throws.
 */
export declare function activeLoginGuard(raw: string | null | undefined, windowSeconds: number, now?: number): string | undefined;
/**
 * Is this `prompt` an explicit user action that starts a fresh attempt?
 * `login` and `select_account` (OIDC Core section 3.1.2.1) ask the user to
 * authenticate or choose an account again, so they are never a loop.
 */
export declare function isExplicitLoginPrompt(prompt: unknown): boolean;
