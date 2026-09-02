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

  it('applies the colon-in-path rule to the percent-decoded form too', () => {
    expect(sanitizeReturnTo('/javascript%3Aalert(1)')).toBeUndefined();
    expect(sanitizeReturnTo('/%6a%61%76%61%73%63%72%69%70%74%3Aalert(1)')).toBeUndefined();
    // A ':' inside the query is still fine in both raw and decoded forms
    expect(sanitizeReturnTo('/resume?next=https%3A%2F%2Fapp.test%2Fx')).toBe(
      '/resume?next=https%3A%2F%2Fapp.test%2Fx',
    );
  });

  it('enforces the length cap (256 by default, overridable)', () => {
    const atMax = '/' + 'a'.repeat(255); // 256 chars
    const overMax = '/' + 'a'.repeat(256); // 257 chars
    expect(atMax).toHaveLength(256);
    expect(overMax).toHaveLength(257);
    expect(sanitizeReturnTo(atMax)).toBe(atMax);
    expect(sanitizeReturnTo(overMax)).toBeUndefined();
    expect(sanitizeReturnTo('/abcdef', 5)).toBeUndefined();
    expect(sanitizeReturnTo('/abcd', 5)).toBe('/abcd');
  });

  describe('encoded-size cap (what actually lands in the cookie)', () => {
    // The cookie serializer stores encodeURIComponent(JSON.stringify(states)),
    // so this is the per-value cost the cap has to bound.
    const encodedLength = (v: string) => encodeURIComponent(JSON.stringify(v)).length;

    it('(a) a 256-char path of ?/=/& passes the character cap but is rejected by the byte cap', () => {
      const v = '/' + '?=&'.repeat(85); // everything after the first '?' → colon rule irrelevant
      expect(v).toHaveLength(256);
      expect(encodedLength(v)).toBeGreaterThan(384);
      expect(sanitizeReturnTo(v)).toBeUndefined();
    });

    it('(b) a 256-char alphanumeric path is still accepted (the two caps agree on plain paths)', () => {
      const v = '/' + 'a'.repeat(255);
      expect(v).toHaveLength(256);
      expect(encodedLength(v)).toBeLessThanOrEqual(384);
      expect(sanitizeReturnTo(v)).toBe(v);
    });

    it('(c) boundary: encoded length 384 accepted, 385 rejected; maxEncodedLength is overridable', () => {
      const at = '/' + '?'.repeat(100) + 'a'.repeat(75); // 9 + 300 + 75
      const over = '/' + '?'.repeat(100) + 'a'.repeat(76);
      expect(encodeURIComponent(JSON.stringify(at))).toHaveLength(384);
      expect(encodeURIComponent(JSON.stringify(over))).toHaveLength(385);
      expect(sanitizeReturnTo(at)).toBe(at);
      expect(sanitizeReturnTo(over)).toBeUndefined();
      expect(sanitizeReturnTo(over, 256, 385)).toBe(over);
    });

    it('(d) five pending attempts, each with a worst-case accepted returnTo, fit in a 4 KB cookie', () => {
      // '"' is the most expensive accepted character: JSON-escaped to \" then
      // percent-encoded to %5C%22, six bytes. Fill to exactly the cap.
      const worst = '/?' + '"'.repeat(62); // 12 + 6 × 62 = 384
      expect(encodedLength(worst)).toBe(384);
      expect(sanitizeReturnTo(worst)).toBe(worst);

      // Realistic attempt shape: 43-char base64url state/nonce/verifier (32
      // random bytes), a production-length callback URL, epoch-ms timestamp.
      const b64url = (seed: string) => (seed.repeat(43)).slice(0, 43);
      const states: OIDCState[] = Array.from({ length: 5 }, (_, i) => ({
        state: b64url(`s${i}`),
        nonce: b64url(`n${i}`),
        codeVerifier: b64url(`v${i}`),
        redirectUri: 'https://gateway.fortiumsoftware.com/auth/callback',
        ts: 1_780_000_000_000 + i,
        returnTo: worst,
      }));

      const cookieValue = encodeURIComponent(serializePendingStates(states));
      // 64 bytes of headroom for the signature and the cookie name.
      expect(cookieValue.length).toBeLessThan(4096 - 64);
    });
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
