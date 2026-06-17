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
/**
 * Parse the raw cookie value into an array of pending states.
 *
 * Backward compatible: if the parsed value is an array, return its valid
 * OIDCState entries; if it is a single OIDCState-shaped object (a cookie
 * written by the OLD single-state version during rollout), wrap it as [obj].
 * Anything else returns []. Never throws.
 */
export declare function parsePendingStates(raw: string | null | undefined): OIDCState[];
/**
 * Append a new pending state, pruning expired entries and capping size.
 *
 * Prune: drop entries whose `ts` is older than `ttlMs` (entries with no `ts`
 * are always kept). Then append `next` and cap to the last `max`, dropping
 * the oldest first.
 */
export declare function appendPendingState(existing: OIDCState[], next: OIDCState, opts?: {
    max?: number;
    ttlMs?: number;
    now?: number;
}): OIDCState[];
/**
 * Find the pending state matching the returned `state` query param.
 */
export declare function selectPendingState(states: OIDCState[], returnedState: string): OIDCState | undefined;
/**
 * Return states with the matched entry removed (other in-flight attempts survive).
 */
export declare function removePendingState(states: OIDCState[], returnedState: string): OIDCState[];
/**
 * Serialize pending states for storage in the cookie.
 */
export declare function serializePendingStates(states: OIDCState[]): string;
