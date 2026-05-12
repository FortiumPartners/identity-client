import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';

/**
 * Plugin-route tests for /auth/widget-token on the Fastify plugin.
 *
 * We instantiate the real Fastify plugin against a mocked global fetch
 * (the only outbound network the plugin makes). Session cookies are
 * forged by calling createSessionToken with the same secret the plugin
 * is configured with — the same shape a real /auth/callback would have
 * produced.
 *
 * Express has no comparable inject() helper without adding supertest;
 * its route logic is byte-equivalent to the Fastify one (mirror-image
 * code at packages/express/src/plugin.ts:367-456 vs
 * packages/fastify/src/plugin.ts:311-410), and the IdentityClient call
 * is covered by tests/widget-token-core.test.ts. So Express coverage is
 * the union of (a) the core test + (b) the Fastify route test of the
 * same exchange logic.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { createSessionToken } from '../packages/core/src/session.js';

const ISSUER = 'https://identity.example.com';
const CLIENT_ID = 'gateway';
const CLIENT_SECRET = 'plugin-test-secret';
const JWT_SECRET = 'plugin-test-jwt-secret-not-real';
const COOKIE_SECRET = 'plugin-test-cookie-secret-not-real';
const SESSION_ISSUER = 'gateway';
const USER_ID = '44a62931-8f59-416d-a482-058ee3e3ab86';
const USER_EMAIL = 'burke@fortium.test';

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
        sessionIssuer: SESSION_ISSUER,
      });
    },
    { prefix: '/auth' },
  );
  return app;
}

async function makeSessionCookie(app: FastifyInstance): Promise<string> {
  // Build a session token the same way /auth/callback would, then sign it
  // with @fastify/cookie's signCookie helper — the plugin's unsign()
  // pipeline rejects unsigned values, so a raw token cookie reads as null.
  const token = await createSessionToken(
    { fortiumUserId: USER_ID, email: USER_EMAIL },
    {
      jwtSecret: JWT_SECRET,
      issuer: SESSION_ISSUER,
      expiresIn: '1h',
    },
  );
  return app.signCookie(token);
}

function mockFetchResolved({
  status = 200,
  body = {},
  ok,
}: { status?: number; body?: unknown; ok?: boolean } = {}) {
  global.fetch = jest.fn<typeof fetch>().mockResolvedValue({
    ok: ok ?? (status >= 200 && status < 300),
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response);
}

function mockFetchRejected(err: Error) {
  global.fetch = jest.fn<typeof fetch>().mockRejectedValue(err);
}

describe('Fastify /auth/widget-token route', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await buildApp();
  });

  afterEach(async () => {
    await app.close();
    global.fetch = realFetch;
  });

  it('audience param missing → 400 with OAuth-compliant error body', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token',
    });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('audience'),
    });
  });

  it('no session cookie → 401', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=ideas-api',
    });
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'unauthorized' });
  });

  it('invalid session cookie → 401', async () => {
    // Forged JWT signed with WRONG jwtSecret. Cookie itself is signed
    // correctly so unsign() succeeds, but verifySessionToken rejects the
    // JWT signature → null session → 401.
    const badJwt = await createSessionToken(
      { fortiumUserId: USER_ID, email: USER_EMAIL },
      { jwtSecret: 'WRONG-SECRET', issuer: SESSION_ISSUER, expiresIn: '1h' },
    );
    const signedCookie = app.signCookie(badJwt);
    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=ideas-api',
      cookies: { auth_token: signedCookie },
    });
    expect(res.statusCode).toBe(401);
  });

  it('happy path → 200 with locked response shape: { accessToken, expiresIn, tokenType, audience }', async () => {
    mockFetchResolved({
      body: {
        access_token: 'fake.jwt.value',
        token_type: 'Bearer',
        expires_in: 300,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        scope: 'ideas:widget',
      },
    });
    const sessionCookie = await makeSessionCookie(app);

    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=ideas-api',
      cookies: { auth_token: sessionCookie },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    // Locked response shape — exactly 4 fields, no extras
    expect(Object.keys(body).sort()).toEqual(
      ['accessToken', 'audience', 'expiresIn', 'tokenType'].sort(),
    );
    expect(body).toEqual({
      accessToken: 'fake.jwt.value',
      expiresIn: 300,
      tokenType: 'Bearer',
      audience: 'ideas-api',
    });

    // Verify the wire call to Identity used the right grant + subject
    const [url, init] = (global.fetch as jest.Mock<typeof fetch>).mock.calls[0];
    expect(url.toString()).toBe(`${ISSUER}/oidc/token`);
    const reqBody = new URLSearchParams((init as RequestInit).body as string);
    expect(reqBody.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(reqBody.get('subject_token')).toBe(USER_ID);
    expect(reqBody.get('audience')).toBe('ideas-api');
  });

  it('Identity returns invalid_target → 400 forwarded with OAuth-compliant body', async () => {
    mockFetchResolved({
      status: 400,
      body: {
        error: 'invalid_target',
        error_description: "audience 'random-api' is not in this client's allowed_exchange_audiences",
      },
    });
    const sessionCookie = await makeSessionCookie(app);

    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=random-api',
      cookies: { auth_token: sessionCookie },
    });

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({
      error: 'invalid_target',
      error_description: expect.stringContaining('allowed_exchange_audiences'),
    });
  });

  it('Identity unreachable (timeout) → 503 with service_unavailable error', async () => {
    mockFetchRejected(
      Object.assign(new Error('signal timed out'), { name: 'TimeoutError' }),
    );
    const sessionCookie = await makeSessionCookie(app);

    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=ideas-api',
      cookies: { auth_token: sessionCookie },
    });

    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body)).toMatchObject({
      error: 'service_unavailable',
    });
  });

  it('Identity 500 → 503 (5xx is upstream error, mapped to service_unavailable)', async () => {
    mockFetchResolved({ status: 500, body: 'internal error' });
    const sessionCookie = await makeSessionCookie(app);

    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=ideas-api',
      cookies: { auth_token: sessionCookie },
    });

    // The core method throws with statusCode=500; the plugin maps anything
    // outside the 4xx range to 503 (service unavailable). 5xx from Identity
    // is a downstream-server problem, not a client-fixable error.
    expect(res.statusCode).toBe(503);
  });
});
