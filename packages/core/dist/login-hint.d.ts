/**
 * OIDC `login_hint` validation, shared by core and both plugins.
 */
/** Longest hint accepted, after trimming: the maximum length of an email address. */
export declare const LOGIN_HINT_MAX_LENGTH = 254;
/**
 * Returns the hint to forward as `login_hint`, or undefined when it must be
 * dropped. Accepted: a string with no control characters anywhere, which is
 * 1 to 254 characters once trimmed. The trimmed form is returned.
 */
export declare function sanitizeLoginHint(raw: unknown): string | undefined;
