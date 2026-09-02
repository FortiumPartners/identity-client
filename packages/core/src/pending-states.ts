/**
 * Pending OIDC auth-attempt state management.
 *
 * The login flow stores the PKCE state (codeVerifier, nonce, redirectUri) in a
 * signed cookie so /callback can resolve the returned code against it. Storing a
 * single state means overlapping authorize flows (double-click "Get Started", a
 * second tab, etc.) clobber each other: attempt N+1 overwrites attempt N's cookie,
 * so N's /callback resolves against N+1's codeVerifier → invalid_grant.
 *
 * These pure helpers store an ARRAY of pending attempts in the cookie and let
 * /callback select the attempt whose `state` matches the returned `state` param,
 * so concurrent flows coexist. No I/O — the caller owns cookie read/write.
 */

import type { OIDCState } from './types.js';

const DEFAULT_MAX = 5;
const DEFAULT_TTL_MS = 600000; // 10 minutes — matches the cookie maxAge

/**
 * Type guard: does a parsed value look like an OIDCState?
 * Requires the two fields /callback strictly needs (state + codeVerifier).
 */
function isOIDCState(value: unknown): value is OIDCState {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { state?: unknown }).state === 'string' &&
    typeof (value as { codeVerifier?: unknown }).codeVerifier === 'string'
  );
}

/**
 * Parse the raw cookie value into an array of pending states.
 *
 * Backward compatible: if the parsed value is an array, return its valid
 * OIDCState entries; if it is a single OIDCState-shaped object (a cookie
 * written by the OLD single-state version during rollout), wrap it as [obj].
 * Anything else returns []. Never throws.
 */
export function parsePendingStates(raw: string | null | undefined): OIDCState[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (Array.isArray(parsed)) {
    return parsed.filter(isOIDCState);
  }
  if (isOIDCState(parsed)) {
    return [parsed];
  }
  return [];
}

/**
 * Append a new pending state, pruning expired entries and capping size.
 *
 * Prune: drop entries whose `ts` is older than `ttlMs` (entries with no `ts`
 * are always kept). Then append `next` and cap to the last `max`, dropping
 * the oldest first.
 */
export function appendPendingState(
  existing: OIDCState[],
  next: OIDCState,
  opts?: { max?: number; ttlMs?: number; now?: number },
): OIDCState[] {
  const max = opts?.max ?? DEFAULT_MAX;
  const ttlMs = opts?.ttlMs ?? DEFAULT_TTL_MS;
  const now = opts?.now ?? Date.now();

  const live = existing.filter((entry) => {
    if (typeof entry.ts !== 'number') return true;
    return now - entry.ts < ttlMs;
  });

  const appended = [...live, next];
  if (appended.length > max) {
    return appended.slice(appended.length - max);
  }
  return appended;
}

/**
 * Find the pending state matching the returned `state` query param.
 */
export function selectPendingState(
  states: OIDCState[],
  returnedState: string,
): OIDCState | undefined {
  return states.find((entry) => entry.state === returnedState);
}

/**
 * Return states with the matched entry removed (other in-flight attempts survive).
 */
export function removePendingState(states: OIDCState[], returnedState: string): OIDCState[] {
  return states.filter((entry) => entry.state !== returnedState);
}

/**
 * Serialize pending states for storage in the cookie.
 */
export function serializePendingStates(states: OIDCState[]): string {
  return JSON.stringify(states);
}

/**
 * Validate a caller-supplied post-login landing path (`?returnTo=` on /login).
 *
 * The plugin appends the value to its frontendUrl, so it must be a same-origin
 * relative path and nothing else:
 * - exactly one leading `/` (`//host` and `/\host` are protocol-relative to browsers)
 * - printable ASCII only (0x20–0x7E): no CR/LF/NUL, and nothing Node would
 *   refuse in a Location header — percent-encode anything else
 * - no `:` before the first `?` or `#` (rules out `/javascript:` and `://`)
 * - at most `maxLength` characters
 * - percent-decodes without throwing, and the decoded form ALSO has exactly one
 *   leading `/` (so `%2F%2F` cannot smuggle a protocol-relative URL through a
 *   downstream router that decodes before redirecting)
 *
 * Returns the ORIGINAL string when it passes, never the decoded form; returns
 * `undefined` otherwise so the caller falls back to its configured default.
 * Pure; never throws.
 */
export function sanitizeReturnTo(raw: unknown, maxLength = 512): string | undefined {
  if (typeof raw !== 'string') return undefined;
  if (raw.length === 0 || raw.length > maxLength) return undefined;
  if (!hasSingleLeadingSlash(raw)) return undefined;

  let inPath = true;
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return undefined;
    const ch = raw[i];
    if (ch === '?' || ch === '#') inPath = false;
    if (inPath && ch === ':') return undefined;
  }

  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return undefined;
  }
  if (!hasSingleLeadingSlash(decoded)) return undefined;

  return raw;
}

function hasSingleLeadingSlash(value: string): boolean {
  return value[0] === '/' && value[1] !== '/' && value[1] !== '\\';
}
