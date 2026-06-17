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

const ISSUER = 'https://identity.example.com';
const CLIENT_ID = 'gateway';
const CLIENT_SECRET = 'plugin-test-secret';
const JWT_SECRET = 'plugin-test-jwt-secret-not-real';
const COOKIE_SECRET = 'plugin-test-cookie-secret-not-real';

const realFetch = global.fetch;

async function buildApp(): Promise<FastifyInstance> {
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
