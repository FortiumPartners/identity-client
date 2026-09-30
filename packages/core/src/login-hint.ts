/**
 * OIDC `login_hint` validation, shared by core and both plugins.
 */

/** Longest hint accepted, after trimming: the maximum length of an email address. */
export const LOGIN_HINT_MAX_LENGTH = 254;

// Unicode Cc: C0 controls, DEL and C1 controls.
const CONTROL_CHARACTER = /\p{Cc}/u;

/**
 * Returns the hint to forward as `login_hint`, or undefined when it must be
 * dropped. Accepted: a string with no control characters anywhere, which is
 * 1 to 254 characters once trimmed. The trimmed form is returned.
 */
export function sanitizeLoginHint(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  if (CONTROL_CHARACTER.test(raw)) return undefined;
  const hint = raw.trim();
  if (hint.length === 0 || hint.length > LOGIN_HINT_MAX_LENGTH) return undefined;
  return hint;
}
