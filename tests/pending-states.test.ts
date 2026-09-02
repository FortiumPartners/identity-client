import { describe, it, expect } from '@jest/globals';
import {
  parsePendingStates,
  appendPendingState,
  selectPendingState,
  removePendingState,
  serializePendingStates,
  sanitizeReturnTo,
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

describe('sanitizeReturnTo', () => {
  it('accepts a relative path and returns it unchanged', () => {
    expect(sanitizeReturnTo('/nda')).toBe('/nda');
    expect(sanitizeReturnTo('/candidates/123/step?x=1#frag')).toBe('/candidates/123/step?x=1#frag');
    expect(sanitizeReturnTo('/')).toBe('/');
    // `:` is only forbidden in the path segment — a URL inside the query is fine
    expect(sanitizeReturnTo('/resume?next=https://app.test/x')).toBe('/resume?next=https://app.test/x');
    // Non-ASCII must arrive percent-encoded; the encoded form is returned as-is
    expect(sanitizeReturnTo('/candidates/Jos%C3%A9')).toBe('/candidates/Jos%C3%A9');
  });

  it('rejects non-strings and the empty string', () => {
    expect(sanitizeReturnTo(undefined)).toBeUndefined();
    expect(sanitizeReturnTo(null)).toBeUndefined();
    expect(sanitizeReturnTo(42)).toBeUndefined();
    expect(sanitizeReturnTo(['/a', '/b'])).toBeUndefined(); // ?returnTo=/a&returnTo=/b parses as an array
    expect(sanitizeReturnTo('')).toBeUndefined();
  });

  it('rejects anything that is not a single-leading-slash path', () => {
    expect(sanitizeReturnTo('nda')).toBeUndefined();
    expect(sanitizeReturnTo('//evil.com')).toBeUndefined();
    expect(sanitizeReturnTo('/\\evil.com')).toBeUndefined();
    expect(sanitizeReturnTo('https://evil.com/x')).toBeUndefined();
    expect(sanitizeReturnTo('/javascript:alert(1)')).toBeUndefined();
    expect(sanitizeReturnTo(' //evil.com')).toBeUndefined();
  });

  it('rejects control characters and non-ASCII (header injection; Node refuses them in Location)', () => {
    expect(sanitizeReturnTo('/x\r\nSet-Cookie: a=b')).toBeUndefined();
    expect(sanitizeReturnTo('/x\n')).toBeUndefined();
    expect(sanitizeReturnTo('/x\0')).toBeUndefined();
    expect(sanitizeReturnTo('/caf\u00e9')).toBeUndefined();
  });

  it('rejects values whose percent-decoded form escapes the origin, or that do not decode', () => {
    expect(sanitizeReturnTo('/%2F%2Fevil.com')).toBeUndefined();
    expect(sanitizeReturnTo('/%2f%2fevil.com')).toBeUndefined();
    expect(sanitizeReturnTo('/%5Cevil.com')).toBeUndefined();
    expect(sanitizeReturnTo('/%')).toBeUndefined(); // malformed escape → decodeURIComponent throws
    expect(sanitizeReturnTo('/%E0%A4%A')).toBeUndefined();
  });

  it('enforces the length cap (512 by default, overridable)', () => {
    const atMax = '/' + 'a'.repeat(511); // 512 chars
    const overMax = '/' + 'a'.repeat(512); // 513 chars
    expect(sanitizeReturnTo(atMax)).toBe(atMax);
    expect(sanitizeReturnTo(overMax)).toBeUndefined();
    expect(sanitizeReturnTo('/abcdef', 5)).toBeUndefined();
    expect(sanitizeReturnTo('/abcd', 5)).toBe('/abcd');
  });

  it('round-trip: an OIDCState with returnTo survives serialize → parse intact', () => {
    const withReturnTo = mkState({ state: 'rt', returnTo: '/candidates/123/step?x=1#frag' });
    const plain = mkState({ state: 'plain' });
    const parsed = parsePendingStates(serializePendingStates([withReturnTo, plain]));
    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toEqual(withReturnTo);
    expect(parsed[1]).toEqual(plain);
    expect(selectPendingState(parsed, 'rt')?.returnTo).toBe('/candidates/123/step?x=1#frag');
    expect(selectPendingState(parsed, 'plain')?.returnTo).toBeUndefined();
  });
});
