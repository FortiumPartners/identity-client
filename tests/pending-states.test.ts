import { describe, it, expect } from '@jest/globals';
import {
  parsePendingStates,
  appendPendingState,
  selectPendingState,
  removePendingState,
  serializePendingStates,
} from '../packages/core/src/pending-states.js';
import type { OIDCState } from '../packages/core/src/types.js';

function mkState(overrides: Partial<OIDCState> = {}): OIDCState {
  return {
    state: 'state-default',
    nonce: 'nonce-default',
    codeVerifier: 'verifier-default',
    redirectUri: 'https://app.test/auth/callback',
    ts: 1_000_000,
    ...overrides,
  };
}

describe('pending-states helpers', () => {
  it('overlapping flows: each attempt resolves to its own codeVerifier; removing one leaves the other', () => {
    const a = mkState({ state: 'A', codeVerifier: 'verifier-A', nonce: 'nonce-A' });
    const b = mkState({ state: 'B', codeVerifier: 'verifier-B', nonce: 'nonce-B' });

    // Use a fixed `now` near the fixtures' ts so TTL pruning doesn't evict them.
    const now = 1_000_500;
    let states = appendPendingState([], a, { now });
    states = appendPendingState(states, b, { now });

    const selA = selectPendingState(states, 'A');
    const selB = selectPendingState(states, 'B');
    expect(selA?.codeVerifier).toBe('verifier-A');
    expect(selB?.codeVerifier).toBe('verifier-B');

    // Consuming A leaves B intact with its own verifier
    const remaining = removePendingState(states, 'A');
    expect(remaining).toHaveLength(1);
    expect(remaining[0].state).toBe('B');
    expect(remaining[0].codeVerifier).toBe('verifier-B');
    expect(selectPendingState(remaining, 'A')).toBeUndefined();
  });

  it('backward compat: a single old OIDCState object parses as a one-element array', () => {
    const oldObj = mkState({ state: 'OLD', codeVerifier: 'verifier-OLD' });
    const raw = JSON.stringify(oldObj); // OLD version wrote a single object, not an array
    const parsed = parsePendingStates(raw);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toEqual(oldObj);
    // And it is selectable / exchangeable
    expect(selectPendingState(parsed, 'OLD')?.codeVerifier).toBe('verifier-OLD');
  });

  it('cap eviction: appending 7 states with max=5 keeps the last 5, drops the oldest two', () => {
    const now = 1_000_500; // near the fixtures' ts so TTL pruning is not triggered
    let states: OIDCState[] = [];
    for (let i = 0; i < 7; i++) {
      states = appendPendingState(states, mkState({ state: `s${i}`, codeVerifier: `v${i}` }), {
        max: 5,
        now,
      });
    }
    expect(states).toHaveLength(5);
    expect(states.map((s) => s.state)).toEqual(['s2', 's3', 's4', 's5', 's6']);
    expect(selectPendingState(states, 's0')).toBeUndefined();
    expect(selectPendingState(states, 's1')).toBeUndefined();
  });

  it('TTL pruning: entries older than ttlMs are pruned on append; entries without ts are kept', () => {
    const now = 10_000_000;
    const stale = mkState({ state: 'stale', ts: now - 700_000 }); // older than 600000 default
    const fresh = mkState({ state: 'fresh', ts: now - 1_000 });
    const noTs = mkState({ state: 'noTs', ts: undefined });
    const next = mkState({ state: 'next', ts: now });

    const result = appendPendingState([stale, fresh, noTs], next, { now });
    const stateNames = result.map((s) => s.state);
    expect(stateNames).not.toContain('stale'); // pruned
    expect(stateNames).toContain('fresh'); // within ttl
    expect(stateNames).toContain('noTs'); // kept (no ts)
    expect(stateNames).toContain('next'); // appended
  });

  it('robustness: null / undefined / malformed JSON / wrong-shape all return [] and never throw', () => {
    expect(parsePendingStates(null)).toEqual([]);
    expect(parsePendingStates(undefined)).toEqual([]);
    expect(parsePendingStates('')).toEqual([]);
    expect(parsePendingStates('{not valid json')).toEqual([]);
    expect(parsePendingStates('42')).toEqual([]); // valid JSON, wrong shape
    expect(parsePendingStates('"a string"')).toEqual([]);
    expect(parsePendingStates(JSON.stringify({ foo: 'bar' }))).toEqual([]); // object missing state/codeVerifier
    // Array with mixed valid/invalid entries → only valid kept
    const mixed = JSON.stringify([mkState({ state: 'ok' }), { foo: 'bar' }, null]);
    const parsed = parsePendingStates(mixed);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].state).toBe('ok');
  });

  it('serialize round-trips through parse', () => {
    const states = [mkState({ state: 'x' }), mkState({ state: 'y' })];
    expect(parsePendingStates(serializePendingStates(states))).toEqual(states);
  });
});
