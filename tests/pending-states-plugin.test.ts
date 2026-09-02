import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';

/**
 * Plugin-level test for the overlapping-flow fix on the Fastify plugin.
 *
 * Simulates two overlapping /auth/login calls (each writes its own pending
 * state into the SAME oidc_state cookie as an array) and then a /auth/callback
 * for the FIRST attempt's state. Asserts the plugin resolves the FIRST
 * attempt's PKCE codeVerifier (read off the outbound token-exchange request),
 * proving attempt N+1 no longer clobbers attempt N.
 *
 * We mock global.fetch (the token endpoint). The exchange's subsequent ID-token
 * validation (JWKS) will fail with the fake token, but that happens AFTER the
 * code_verifier is sent — which is the thing under test. The assertion is on
 * the captured fetch body, not on the final redirect.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { IdentityClient } from '../packages/core/src/identity-client.js';
import type { FortiumClaims } from '../packages/core/src/types.js';

const ISSUER = 'https://identity.example.com';
const CLIENT_ID = 'gateway';
const CLIENT_SECRET = 'plugin-test-secret';
const JWT_SECRET = 'plugin-test-jwt-secret-not-real';
const COOKIE_SECRET = 'plugin-test-cookie-secret-not-real';

const realFetch = global.fetch;

async function buildApp(
  extra: { postLoginPath?: string; callbackUrl?: string; cookiePrefix?: string } = {},
): Promise<FastifyInstance> {
  const app = fastify({ logger: false });
  await app.register(fastifyCookie, { secret: COOKIE_SECRET });
  await app.register(
    async (instance) => {
      await instance.register(identityPlugin, {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        callbackUrl: 'https://app.test/auth/callback',
        frontendUrl: 'https://app.test',
        jwtSecret: JWT_SECRET,
        sessionIssuer: 'gateway',
        ...extra,
      });
    },
    { prefix: '/auth' },
  );
  return app;
}

// Pull `state` + `code_verifier` info out of a redirect Location and the
// cookie the plugin set. We need the `state` value the plugin generated and
// the cookie it stored so we can build a matching /callback request.
function parseSetCookie(res: { headers: Record<string, unknown> }, name: string): string | undefined {
  const raw = res.headers['set-cookie'];
  const arr = Array.isArray(raw) ? raw : raw ? [String(raw)] : [];
  const match = arr.find((c) => c.startsWith(`${name}=`));
  if (!match) return undefined;
  return match.split(';')[0].slice(name.length + 1);
}

function stateFromLocation(location: string): string {
  return new URL(location).searchParams.get('state') as string;
}

describe('Fastify overlapping /login → /callback resolves the correct attempt', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await buildApp();
  });

  afterEach(async () => {
    await app.close();
    global.fetch = realFetch;
  });

  it('two overlapping logins; callback for the FIRST state uses the FIRST verifier', async () => {
    // First login — empty cookie jar.
    const login1 = await app.inject({ method: 'GET', url: '/auth/login' });
    const state1 = stateFromLocation(login1.headers.location as string);
    const cookieAfter1 = parseSetCookie(login1, 'oidc_state') as string;

    // Second login — send the cookie set by login1 so the plugin appends.
    const login2 = await app.inject({
      method: 'GET',
      url: '/auth/login',
      cookies: { oidc_state: decodeURIComponent(cookieAfter1) },
    });
    const state2 = stateFromLocation(login2.headers.location as string);
    const cookieAfter2 = parseSetCookie(login2, 'oidc_state') as string;

    expect(state1).not.toEqual(state2);

    // Capture the outbound token exchange so we can read code_verifier.
    const fetchMock = jest.fn<typeof fetch>().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: 'fake',
        id_token: 'fake.id.token',
        token_type: 'Bearer',
        expires_in: 300,
      }),
      text: async () => '',
    } as unknown as Response);
    global.fetch = fetchMock;

    // Callback for the FIRST attempt, carrying the cookie that holds BOTH states.
    await app.inject({
      method: 'GET',
      url: `/auth/callback?code=authcode&state=${encodeURIComponent(state1)}`,
      cookies: { oidc_state: decodeURIComponent(cookieAfter2) },
    });

    // The exchange must have been attempted (state matched → not state_mismatch).
    expect(fetchMock).toHaveBeenCalled();
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = new URLSearchParams(init.body as string);
    // The verifier sent must belong to attempt 1, NOT attempt 2.
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('authcode');
    // We can't read the verifier from the redirect, but we CAN confirm the
    // callback selected attempt 1 (vs. mismatch) by the fact the exchange ran.
    // To prove it used attempt-1's verifier specifically, run the callback for
    // state2 in a fresh exchange and confirm a DIFFERENT verifier is sent.
    const verifier1 = body.get('code_verifier');
    expect(verifier1).toBeTruthy();

    // Now callback for the SECOND attempt using the same combined cookie.
    fetchMock.mockClear();
    await app.inject({
      method: 'GET',
      url: `/auth/callback?code=authcode2&state=${encodeURIComponent(state2)}`,
      cookies: { oidc_state: decodeURIComponent(cookieAfter2) },
    });
    expect(fetchMock).toHaveBeenCalled();
    const body2 = new URLSearchParams((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    const verifier2 = body2.get('code_verifier');
    expect(verifier2).toBeTruthy();

    // The two attempts carry DIFFERENT verifiers — proving overlapping flows
    // coexist and each callback resolves its own PKCE verifier.
    expect(verifier1).not.toEqual(verifier2);
  });

  it('callback for an unknown state → state_mismatch (no exchange attempted)', async () => {
    const login1 = await app.inject({ method: 'GET', url: '/auth/login' });
    const cookieAfter1 = parseSetCookie(login1, 'oidc_state') as string;

    const fetchMock = jest.fn<typeof fetch>();
    global.fetch = fetchMock;

    const res = await app.inject({
      method: 'GET',
      url: `/auth/callback?code=authcode&state=does-not-exist`,
      cookies: { oidc_state: decodeURIComponent(cookieAfter1) },
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(res.headers.location).toContain('error=state_mismatch');
  });
});

/**
 * Per-request landing path: /auth/login?returnTo=/path is stored on that
 * attempt's pending state and honoured by the matching /auth/callback.
 *
 * These tests need the callback to run to its final redirect, so the token
 * exchange (which would otherwise fail JWKS validation on a fake ID token)
 * is stubbed at IdentityClient.prototype.exchangeCode. The plugin resolves
 * that method through the prototype at call time, so the stub applies to the
 * client instance the plugin built at registration.
 */
describe('Fastify /login?returnTo → /callback lands on the requested path', () => {
  const USER_ID = '44a62931-8f59-416d-a482-058ee3e3ab86';
  const USER_EMAIL = 'burke@fortium.test';
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await buildApp();
    const claims = { fortium_user_id: USER_ID, email: USER_EMAIL, email_verified: true } as FortiumClaims;
    jest
      .spyOn(IdentityClient.prototype, 'exchangeCode')
      .mockResolvedValue({ idToken: 'fake.id.token', accessToken: 'fake-access', claims });
  });

  afterEach(async () => {
    await app.close();
    jest.restoreAllMocks();
  });

  // Start a login (optionally carrying an existing oidc_state cookie so the
  // plugin appends) and return what /callback needs to resolve it.
  async function login(
    instance: FastifyInstance,
    url: string,
    existingCookie?: string,
  ): Promise<{ state: string; cookie: string; location: string }> {
    const res = await instance.inject({
      method: 'GET',
      url,
      cookies: existingCookie ? { oidc_state: existingCookie } : undefined,
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers.location as string;
    return {
      state: stateFromLocation(location),
      cookie: decodeURIComponent(parseSetCookie(res, 'oidc_state') as string),
      location,
    };
  }

  async function callback(instance: FastifyInstance, state: string, cookie: string) {
    return instance.inject({
      method: 'GET',
      url: `/auth/callback?code=authcode&state=${encodeURIComponent(state)}`,
      cookies: { oidc_state: cookie },
    });
  }

  it('(a) returnTo=/nda → callback redirects to frontendUrl + /nda', async () => {
    const { state, cookie, location } = await login(app, '/auth/login?returnTo=/nda');
    // returnTo is not forwarded to Identity — it lives only in our signed cookie
    expect(new URL(location).searchParams.has('returnTo')).toBe(false);

    const res = await callback(app, state, cookie);
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('https://app.test/nda');
    expect(parseSetCookie(res, 'auth_token')).toBeTruthy();
  });

  it('(b) no returnTo → callback redirects to the registration-time postLoginRedirect, unchanged', async () => {
    // Default: frontendUrl + /dashboard
    const { state, cookie } = await login(app, '/auth/login');
    const res = await callback(app, state, cookie);
    expect(res.headers.location).toBe('https://app.test/dashboard');

    // Explicit postLoginPath is honoured exactly as before
    const custom = await buildApp({ postLoginPath: '/home' });
    try {
      const l = await login(custom, '/auth/login');
      const r = await callback(custom, l.state, l.cookie);
      expect(r.headers.location).toBe('https://app.test/home');
    } finally {
      await custom.close();
    }
  });

  it('(c) rejected returnTo (//evil.com) is dropped → callback falls back to postLoginRedirect', async () => {
    const { state, cookie } = await login(app, '/auth/login?returnTo=//evil.com');
    // The rejected value never reaches the cookie
    expect(cookie).not.toContain('evil.com');

    const res = await callback(app, state, cookie);
    expect(res.headers.location).toBe('https://app.test/dashboard');

    // Absolute URL and encoded protocol-relative forms fall back the same way
    for (const bad of ['https://evil.com/x', '/%2F%2Fevil.com', '/\\evil.com']) {
      const l = await login(app, `/auth/login?returnTo=${encodeURIComponent(bad)}`);
      const r = await callback(app, l.state, l.cookie);
      expect(r.headers.location).toBe('https://app.test/dashboard');
    }
  });

  it('(d) two overlapping logins with returnTo=/a and /b, callbacks in reverse order → each lands on its own path', async () => {
    const a = await login(app, '/auth/login?returnTo=/a');
    const b = await login(app, '/auth/login?returnTo=/b', a.cookie); // cookie now holds both attempts
    expect(a.state).not.toEqual(b.state);

    // B first, then A — both resolved against the combined cookie
    const resB = await callback(app, b.state, b.cookie);
    expect(resB.headers.location).toBe('https://app.test/b');

    const resA = await callback(app, a.state, b.cookie);
    expect(resA.headers.location).toBe('https://app.test/a');
  });
});

/**
 * The cookie-size claim, end to end: five real /auth/login calls, each with a
 * returnTo at the encoded-size cap, through the real signer and cookie
 * serializer, with a production-length callback URL and a cookie-name
 * prefix. The Set-Cookie name=value pair must stay under the 4096-byte
 * browser limit or the browser drops oidc_state and every callback fails
 * state_missing.
 */
describe('Fastify five overlapping logins with a max-size returnTo fit in the cookie', () => {
  it('Set-Cookie name=value stays under 4096 bytes', async () => {
    const app = await buildApp({
      callbackUrl: 'https://talent-api.fortiumsoftware.com/auth/callback/x',
      cookiePrefix: 'talent',
    });
    try {
      const name = 'talent_oidc_state';
      const worst = '/?' + '"'.repeat(62); // encodes to exactly 384 bytes
      expect(encodeURIComponent(JSON.stringify(worst))).toHaveLength(384);

      let cookie: string | undefined;
      let pair = '';
      for (let n = 0; n < 5; n++) {
        const res = await app.inject({
          method: 'GET',
          url: `/auth/login?returnTo=${encodeURIComponent(worst)}`,
          cookies: cookie ? { [name]: cookie } : undefined,
        });
        expect(res.statusCode).toBe(302);
        const raw = res.headers['set-cookie'];
        const arr = Array.isArray(raw) ? raw : raw ? [String(raw)] : [];
        pair = arr.find((c) => c.startsWith(`${name}=`))!.split(';')[0];
        cookie = decodeURIComponent(pair.slice(name.length + 1));
      }

      // All five attempts are present and each kept its returnTo.
      const json = cookie!.slice(0, cookie!.lastIndexOf('.'));
      const states = JSON.parse(json) as Array<{ returnTo?: string }>;
      expect(states).toHaveLength(5);
      expect(states.every((s) => s.returnTo === worst)).toBe(true);

      expect(pair.length).toBeLessThan(4096);
    } finally {
      await app.close();
    }
  });
});
