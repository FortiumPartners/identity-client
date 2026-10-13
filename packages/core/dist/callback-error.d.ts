/**
 * OAuth / OIDC error codes an authorization server can return on the redirect
 * to /callback, shared by both plugins.
 */
/**
 * RFC 6749 section 4.1.2.1 and OIDC Core section 3.1.2.6. A code outside this
 * list is not forwarded, so a crafted `?error=` cannot put its own text in the
 * app's /login URL.
 */
export declare const CALLBACK_ERROR_CODES: ReadonlySet<string>;
/**
 * Returns the error code to forward as `/login?error=<code>`, or undefined when
 * the value is not a registered code (not a string, repeated, or unknown).
 * `error_description` and `error_uri` have no counterpart here: they are never
 * read, so they cannot reach a URL.
 */
export declare function sanitizeCallbackError(raw: unknown): string | undefined;
