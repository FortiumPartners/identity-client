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
const DEFAULT_MAX = 5;
const DEFAULT_TTL_MS = 600000; // 10 minutes — matches the cookie maxAge
/**
 * Type guard: does a parsed value look like an OIDCState?
 * Requires the two fields /callback strictly needs (state + codeVerifier).
 */
function isOIDCState(value) {
    return (typeof value === 'object' &&
        value !== null &&
        typeof value.state === 'string' &&
        typeof value.codeVerifier === 'string');
}
/**
 * Parse the raw cookie value into an array of pending states.
 *
 * Backward compatible: if the parsed value is an array, return its valid
 * OIDCState entries; if it is a single OIDCState-shaped object (a cookie
 * written by the OLD single-state version during rollout), wrap it as [obj].
 * Anything else returns []. Never throws.
 */
export function parsePendingStates(raw) {
    if (!raw)
        return [];
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
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
export function appendPendingState(existing, next, opts) {
    const max = opts?.max ?? DEFAULT_MAX;
    const ttlMs = opts?.ttlMs ?? DEFAULT_TTL_MS;
    const now = opts?.now ?? Date.now();
    const live = existing.filter((entry) => {
        if (typeof entry.ts !== 'number')
            return true;
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
export function selectPendingState(states, returnedState) {
    return states.find((entry) => entry.state === returnedState);
}
/**
 * Return states with the matched entry removed (other in-flight attempts survive).
 */
export function removePendingState(states, returnedState) {
    return states.filter((entry) => entry.state !== returnedState);
}
/**
 * Serialize pending states for storage in the cookie.
 */
export function serializePendingStates(states) {
    return JSON.stringify(states);
}
