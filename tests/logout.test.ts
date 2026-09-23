import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';

/**
 * RP-initiated logout must carry client_id (#15).
 *
 * Without an id_token_hint, oidc-provider can only tie
 * post_logout_redirect_uri to a client through client_id; with neither, the
 * user is left on Identity's Signed Out page instead of returning to the app.
 * client_id is sent with the hint too (the ID token's audience is the same
 * client), so the hint-present URL gains client_id and is otherwise unchanged.
 *
 * Express builds its logout URL through the same IdentityClient.getLogoutUrl
 * call as Fastify (packages/express/src/plugin.ts POST/GET /logout), so its
 * coverage is the core test plus the Fastify route tests below.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { IdentityClient } from '../packages/core/src/identity-client.js';

const ISSUER = 'https://identity.example.com';
const CLIENT_ID = 'gateway';
const CLIENT_SECRET = 'plugin-test-secret';
const JWT_SECRET = 'plugin-test-jwt-secret-not-real';
const COOKIE_SECRET = 'plugin-test-cookie-secret-not-real';
const ID_TOKEN = 'header.payload.signature';
const POST_LOGOUT = 'https://app.test/login';

function params(url: string): URLSearchParams {
  const parsed = new URL(url);
  expect(`${parsed.origin}${parsed.pathname}`).toBe(`${ISSUER}/oidc/session/end`);
  return parsed.searchParams;
}

describe('IdentityClient.getLogoutUrl', () => {
  const client = new IdentityClient({ issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });

  it('no hint → client_id and post_logout_redirect_uri, no id_token_hint', () => {
    const p = params(client.getLogoutUrl(undefined, POST_LOGOUT));
    expect(p.get('client_id')).toBe(CLIENT_ID);
    expect(p.get('post_logout_redirect_uri')).toBe(POST_LOGOUT);
    expect(p.has('id_token_hint')).toBe(false);
  });

  it('hint present → id_token_hint, client_id and post_logout_redirect_uri', () => {
    const p = params(client.getLogoutUrl(ID_TOKEN, POST_LOGOUT));
    expect(p.get('id_token_hint')).toBe(ID_TOKEN);
    expect(p.get('client_id')).toBe(CLIENT_ID);
    expect(p.get('post_logout_redirect_uri')).toBe(POST_LOGOUT);
  });
});

describe('Fastify /auth/logout', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = fastify({ logger: false });
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
  });

  afterEach(async () => {
    await app.close();
  });

  // GET redirects to the end-session URL; POST returns it for an SPA to follow.
  async function logoutUrl(method: 'GET' | 'POST', cookies?: Record<string, string>): Promise<string> {
    const res = await app.inject({ method, url: '/auth/logout', cookies });
    if (method === 'GET') {
      expect(res.statusCode).toBe(302);
      return res.headers.location as string;
    }
    expect(res.statusCode).toBe(200);
    return (JSON.parse(res.body) as { logoutUrl: string }).logoutUrl;
  }

  for (const method of ['GET', 'POST'] as const) {
    it(`${method}: no id_token cookie → client_id and post_logout_redirect_uri, no id_token_hint`, async () => {
      const p = params(await logoutUrl(method));
      expect(p.get('client_id')).toBe(CLIENT_ID);
      expect(p.get('post_logout_redirect_uri')).toBe(POST_LOGOUT);
      expect(p.has('id_token_hint')).toBe(false);
    });

    it(`${method}: id_token cookie that fails to unsign → client_id, no id_token_hint`, async () => {
      const p = params(await logoutUrl(method, { id_token: `${ID_TOKEN}.not-a-valid-signature` }));
      expect(p.get('client_id')).toBe(CLIENT_ID);
      expect(p.get('post_logout_redirect_uri')).toBe(POST_LOGOUT);
      expect(p.has('id_token_hint')).toBe(false);
    });

    it(`${method}: signed id_token cookie → id_token_hint plus client_id`, async () => {
      const p = params(await logoutUrl(method, { id_token: app.signCookie(ID_TOKEN) }));
      expect(p.get('id_token_hint')).toBe(ID_TOKEN);
      expect(p.get('client_id')).toBe(CLIENT_ID);
      expect(p.get('post_logout_redirect_uri')).toBe(POST_LOGOUT);
    });
  }
});
