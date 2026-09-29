import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';
import express from 'express';
import cookieParser from 'cookie-parser';

/**
 * The widget-token route's subject_token is the user's own Identity access
 * token (Identity #63, 1.4.0), on BOTH plugins.
 *
 * Covers: the access-token cookie written at /callback and /refresh with the
 * other auth cookies' options; the widget route using a live token without
 * refreshing; refreshing exactly once when the token is expired or missing
 * and writing back the rotated refresh token; 401 when no usable token can
 * be had; and concurrent refreshes of one refresh token sharing one call
 * within a single process (the only scope the in-memory coalescing covers).
 *
 * The same suite runs against the Fastify plugin (app.inject) and the Express
 * router (a real listener on an ephemeral port, driven with the unmocked
 * fetch). global.fetch is mocked as Identity's /oidc/token and answers by
 * grant_type. /callback's code exchange and /refresh's ID-token check are
 * stubbed on IdentityClient.prototype, since both need JWKS.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { createIdentityRouter } from '../packages/express/src/plugin.js';
import { IdentityClient } from '../packages/core/src/identity-client.js';
import { createSessionToken } from '../packages/core/src/session.js';
import {
  serializeAccessToken,
  usableAccessToken,
  ACCESS_TOKEN_EXPIRY_SKEW_MS,
} from '../packages/core/src/access-token-cookie.js';
import type { FortiumClaims } from '../packages/core/src/types.js';

const ISSUER = 'https://identity.example.com';
const CLIENT_ID = 'gateway';
const CLIENT_SECRET = 'plugin-test-secret';
const JWT_SECRET = 'plugin-test-jwt-secret-not-real';
const COOKIE_SECRET = 'plugin-test-cookie-secret-not-real';
const SESSION_ISSUER = 'gateway';
const USER_ID = '44a62931-8f59-416d-a482-058ee3e3ab86';
const USER_EMAIL = 'burke@fortium.test';

const LIVE_TOKEN = 'o2m5Vq8xLr3TnK1bWcYd7EhJf0AsGpZuQiXe4MvNt9k';
const EXPIRED_TOKEN = 'xExpiredxLr3TnK1bWcYd7EhJf0AsGpZuQiXe4MvNt9';
const REFRESHED_TOKEN = 'rRefreshedr3TnK1bWcYd7EhJf0AsGpZuQiXe4MvNt9';
const REFRESH_TOKEN = 'refresh-token-original';
const ROTATED_REFRESH_TOKEN = 'refresh-token-rotated';

const realFetch = global.fetch;

const pluginOpts = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackUrl: 'https://app.test/auth/callback',
  frontendUrl: 'https://app.test',
  jwtSecret: JWT_SECRET,
  sessionIssuer: SESSION_ISSUER,
};

interface HarnessResponse {
  status: number;
  body: string;
  location?: string;
  setCookies: string[];
}

interface Harness {
  /** Sign a cookie value the way this framework's cookie signer does. */
  sign(value: string): string;
  /** Unsign a signed cookie value, or null if the signature fails. */
  unsign(signed: string): string | null;
  /** Send a request carrying the given (signed, unencoded) cookie values. */
  request(method: 'GET' | 'POST', url: string, cookies?: Record<string, string>): Promise<HarnessResponse>;
  close(): Promise<void>;
}

async function fastifyHarness(): Promise<Harness> {
  const app: FastifyInstance = fastify({ logger: false });
  await app.register(fastifyCookie, { secret: COOKIE_SECRET });
  await app.register(
    async (instance) => {
      await instance.register(identityPlugin, pluginOpts);
    },
    { prefix: '/auth' },
  );
  return {
    sign: (value) => app.signCookie(value),
    unsign: (signed) => {
      const r = app.unsignCookie(signed);
      return r.valid ? r.value : null;
    },
    async request(method, url, cookies) {
      const res = await app.inject({ method, url, cookies });
      const raw = res.headers['set-cookie'];
      return {
        status: res.statusCode,
        body: res.body,
        location: res.headers.location as string | undefined,
        setCookies: Array.isArray(raw) ? raw : raw ? [String(raw)] : [],
      };
    },
    close: () => app.close(),
  };
}

// cookie-parser's signed-cookie format: "s:" + value + "." + base64 HMAC-SHA256.
function expressSign(value: string): string {
  const mac = createHmac('sha256', COOKIE_SECRET).update(value).digest('base64').replace(/=+$/, '');
  return `s:${value}.${mac}`;
}

function expressUnsign(signed: string): string | null {
  if (!signed.startsWith('s:')) return null;
  const body = signed.slice(2);
  const value = body.slice(0, body.lastIndexOf('.'));
  const expected = Buffer.from(expressSign(value));
  const actual = Buffer.from(signed);
  return expected.length === actual.length && timingSafeEqual(expected, actual) ? value : null;
}

async function expressHarness(): Promise<Harness> {
  const app = express();
  app.use(cookieParser(COOKIE_SECRET));
  app.use('/auth', createIdentityRouter(pluginOpts));
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    sign: expressSign,
    unsign: expressUnsign,
    async request(method, url, cookies) {
      const cookieHeader = Object.entries(cookies ?? {})
        .map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
        .join('; ');
      const res = await realFetch(`http://127.0.0.1:${port}${url}`, {
        method,
        headers: cookieHeader ? { cookie: cookieHeader } : {},
        redirect: 'manual',
      });
      return {
        status: res.status,
        body: await res.text(),
        location: res.headers.get('location') ?? undefined,
        setCookies: res.headers.getSetCookie(),
      };
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** The Set-Cookie line for `name`, split into its value and lower-cased attributes. */
function findSetCookie(res: HarnessResponse, name: string): { value: string; attrs: Record<string, string> } | undefined {
  const line = res.setCookies.find((c) => c.startsWith(`${name}=`));
  if (!line) return undefined;
  const [pair, ...rest] = line.split(';').map((p) => p.trim());
  const attrs: Record<string, string> = {};
  for (const a of rest) {
    const i = a.indexOf('=');
    attrs[(i === -1 ? a : a.slice(0, i)).toLowerCase()] = i === -1 ? 'true' : a.slice(i + 1);
  }
  return { value: decodeURIComponent(pair.slice(name.length + 1)), attrs };
}

type TokenReply = { status?: number; body: Record<string, unknown> } | Error;

/**
 * Mock Identity's /oidc/token, answering by grant_type. `refreshDelayMs`
 * holds the refresh response so concurrent requests overlap.
 */
function mockIdentity({
  refresh = { body: { access_token: REFRESHED_TOKEN, refresh_token: ROTATED_REFRESH_TOKEN, id_token: 'fake.id.token', token_type: 'Bearer', expires_in: 900 } },
  exchange = { body: { access_token: 'minted.widget.jwt', token_type: 'Bearer', expires_in: 300 } },
  refreshDelayMs = 0,
}: { refresh?: TokenReply; exchange?: TokenReply; refreshDelayMs?: number } = {}) {
  const fetchMock = jest.fn<typeof fetch>(async (_url, init) => {
    const grant = new URLSearchParams((init as RequestInit).body as string).get('grant_type');
    const reply = grant === 'refresh_token' ? refresh : exchange;
    if (grant === 'refresh_token' && refreshDelayMs) {
      await new Promise((r) => setTimeout(r, refreshDelayMs));
    }
    if (reply instanceof Error) throw reply;
    const status = reply.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => reply.body,
      text: async () => JSON.stringify(reply.body),
    } as unknown as Response;
  });
  global.fetch = fetchMock;
  return fetchMock;
}

function callsTo(fetchMock: jest.Mock<typeof fetch>) {
  return fetchMock.mock.calls.map(([, init]) => new URLSearchParams((init as RequestInit).body as string));
}

const HARNESSES: Array<[string, () => Promise<Harness>]> = [
  ['Fastify', fastifyHarness],
  ['Express', expressHarness],
];

describe.each(HARNESSES)('%s plugin: access token as the widget subject', (_name, build) => {
  let h: Harness;
  let sessionCookie: string;

  beforeEach(async () => {
    h = await build();
    sessionCookie = h.sign(
      await createSessionToken(
        { fortiumUserId: USER_ID, email: USER_EMAIL },
        { jwtSecret: JWT_SECRET, issuer: SESSION_ISSUER, expiresIn: '1h' },
      ),
    );
  });

  afterEach(async () => {
    await h.close();
    global.fetch = realFetch;
    jest.restoreAllMocks();
  });

  const accessCookie = (token: string, expiresIn: number, issuedAt = Date.now()) =>
    h.sign(serializeAccessToken(token, expiresIn, issuedAt));

  function widget(cookies: Record<string, string>) {
    return h.request('GET', '/auth/widget-token?audience=ideas-api', { auth_token: sessionCookie, ...cookies });
  }

  it('/callback stores the access token with the auth cookies\' options and a max age of expires_in', async () => {
    const claims = { fortium_user_id: USER_ID, email: USER_EMAIL, email_verified: true } as FortiumClaims;
    jest
      .spyOn(IdentityClient.prototype, 'exchangeCode')
      .mockResolvedValue({ idToken: 'fake.id.token', accessToken: LIVE_TOKEN, expiresIn: 3600, refreshToken: REFRESH_TOKEN, claims });

    const login = await h.request('GET', '/auth/login');
    const state = new URL(login.location as string).searchParams.get('state') as string;
    const oidcState = findSetCookie(login, 'oidc_state')!.value;

    const before = Date.now();
    const res = await h.request('GET', `/auth/callback?code=authcode&state=${encodeURIComponent(state)}`, {
      oidc_state: oidcState,
    });
    expect(res.status).toBe(302);
    expect(res.location).toBe('https://app.test/dashboard');

    const access = findSetCookie(res, 'identity_access_token');
    const auth = findSetCookie(res, 'auth_token');
    expect(access).toBeDefined();
    expect(auth).toBeDefined();
    expect(access!.attrs['max-age']).toBe('3600');
    expect(access!.attrs.httponly).toBe('true');
    const { 'max-age': _a, expires: _ae, ...accessRest } = access!.attrs;
    const { 'max-age': _b, expires: _be, ...authRest } = auth!.attrs;
    expect(accessRest).toEqual(authRest);

    const stored = JSON.parse(h.unsign(access!.value) as string);
    expect(stored.t).toBe(LIVE_TOKEN);
    expect(stored.exp).toBeGreaterThanOrEqual(before + 3600_000);
    expect(stored.exp).toBeLessThanOrEqual(Date.now() + 3600_000);
  });

  it('/refresh stores the refreshed access token with a max age of the new expires_in', async () => {
    const claims = { fortium_user_id: USER_ID, email: USER_EMAIL, email_verified: true } as FortiumClaims;
    jest.spyOn(IdentityClient.prototype, 'validateIdToken').mockResolvedValue(claims);
    const fetchMock = mockIdentity();

    const res = await h.request('POST', '/auth/refresh', { refresh_token: h.sign(REFRESH_TOKEN) });
    expect(res.status).toBe(200);
    expect(callsTo(fetchMock).map((b) => b.get('refresh_token'))).toEqual([REFRESH_TOKEN]);

    const access = findSetCookie(res, 'identity_access_token');
    expect(access!.attrs['max-age']).toBe('900');
    expect(JSON.parse(h.unsign(access!.value) as string).t).toBe(REFRESHED_TOKEN);
    expect(h.unsign(findSetCookie(res, 'refresh_token')!.value)).toBe(ROTATED_REFRESH_TOKEN);
  });

  it('valid access token → exchanged as subject_token, no refresh, no cookie rewritten', async () => {
    const fetchMock = mockIdentity();

    const res = await widget({
      identity_access_token: accessCookie(LIVE_TOKEN, 3600),
      refresh_token: h.sign(REFRESH_TOKEN),
    });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({
      accessToken: 'minted.widget.jwt',
      expiresIn: 300,
      tokenType: 'Bearer',
      audience: 'ideas-api',
    });
    const calls = callsTo(fetchMock);
    expect(calls.map((b) => b.get('grant_type'))).toEqual(['urn:ietf:params:oauth:grant-type:token-exchange']);
    expect(calls[0].get('subject_token')).toBe(LIVE_TOKEN);
    expect(calls[0].get('subject_token_type')).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(findSetCookie(res, 'refresh_token')).toBeUndefined();
    expect(findSetCookie(res, 'identity_access_token')).toBeUndefined();
  });

  it('expired access token → exactly one refresh, then the exchange uses the refreshed token; rotated refresh token written back', async () => {
    const fetchMock = mockIdentity();

    const res = await widget({
      identity_access_token: accessCookie(EXPIRED_TOKEN, 3600, Date.now() - 2 * 3600_000),
      refresh_token: h.sign(REFRESH_TOKEN),
    });

    expect(res.status).toBe(200);
    const calls = callsTo(fetchMock);
    expect(calls.map((b) => b.get('grant_type'))).toEqual([
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:token-exchange',
    ]);
    expect(calls[0].get('refresh_token')).toBe(REFRESH_TOKEN);
    expect(calls[1].get('subject_token')).toBe(REFRESHED_TOKEN);

    expect(h.unsign(findSetCookie(res, 'refresh_token')!.value)).toBe(ROTATED_REFRESH_TOKEN);
    const access = findSetCookie(res, 'identity_access_token');
    expect(access!.attrs['max-age']).toBe('900');
    expect(JSON.parse(h.unsign(access!.value) as string).t).toBe(REFRESHED_TOKEN);
  });

  it('access token cookie gone (browser expired it) → one refresh, then exchange', async () => {
    const fetchMock = mockIdentity();

    const res = await widget({ refresh_token: h.sign(REFRESH_TOKEN) });

    expect(res.status).toBe(200);
    const calls = callsTo(fetchMock);
    expect(calls.map((b) => b.get('grant_type'))).toEqual([
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:token-exchange',
    ]);
    expect(calls[1].get('subject_token')).toBe(REFRESHED_TOKEN);
  });

  it('no usable access token and no refresh token → 401, Identity never called', async () => {
    const fetchMock = mockIdentity();

    const expired = await widget({
      identity_access_token: accessCookie(EXPIRED_TOKEN, 3600, Date.now() - 2 * 3600_000),
    });
    const none = await widget({});

    for (const res of [expired, none]) {
      expect(res.status).toBe(401);
      expect(JSON.parse(res.body)).toMatchObject({ error: 'unauthorized' });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refresh refused by Identity (400 invalid_grant) → 401, no exchange', async () => {
    const fetchMock = mockIdentity({
      refresh: { status: 400, body: { error: 'invalid_grant', error_description: 'grant request is invalid' } },
    });

    const res = await widget({ refresh_token: h.sign(REFRESH_TOKEN) });

    expect(res.status).toBe(401);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'unauthorized' });
    expect(callsTo(fetchMock).map((b) => b.get('grant_type'))).toEqual(['refresh_token']);
  });

  it('refresh rate-limited by Identity (429) → retryable 503, not a re-login', async () => {
    const fetchMock = mockIdentity({
      refresh: { status: 429, body: { error: 'too_many_requests' } },
    });

    const res = await widget({ refresh_token: h.sign(REFRESH_TOKEN) });

    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'service_unavailable' });
    expect(callsTo(fetchMock).map((b) => b.get('grant_type'))).toEqual(['refresh_token']);
  });

  it('refresh hits an Identity 5xx → retryable 503', async () => {
    mockIdentity({ refresh: { status: 502, body: { error: 'bad_gateway' } } });

    const res = await widget({ refresh_token: h.sign(REFRESH_TOKEN) });

    expect(res.status).toBe(503);
  });

  it('refresh cannot reach Identity → 503, no exchange', async () => {
    const fetchMock = mockIdentity({ refresh: new TypeError('fetch failed') });

    const res = await widget({ refresh_token: h.sign(REFRESH_TOKEN) });

    expect(res.status).toBe(503);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'service_unavailable' });
    expect(callsTo(fetchMock).map((b) => b.get('grant_type'))).toEqual(['refresh_token']);
  });

  it('two concurrent requests to ONE instance with the same expired token share one refresh', async () => {
    const fetchMock = mockIdentity({ refreshDelayMs: 100 });
    const cookies = {
      identity_access_token: accessCookie(EXPIRED_TOKEN, 3600, Date.now() - 2 * 3600_000),
      refresh_token: h.sign(REFRESH_TOKEN),
    };

    const [a, b] = await Promise.all([widget(cookies), widget(cookies)]);

    expect([a.status, b.status]).toEqual([200, 200]);
    const grants = callsTo(fetchMock).map((c) => c.get('grant_type'));
    expect(grants.filter((g) => g === 'refresh_token')).toHaveLength(1);
    expect(grants.filter((g) => g === 'urn:ietf:params:oauth:grant-type:token-exchange')).toHaveLength(2);
  });

  it('logout clears the access token cookie', async () => {
    const res = await h.request('POST', '/auth/logout', {
      auth_token: sessionCookie,
      identity_access_token: accessCookie(LIVE_TOKEN, 3600),
    });
    const cleared = findSetCookie(res, 'identity_access_token');
    expect(cleared).toBeDefined();
    expect(cleared!.value).toBe('');
  });
});

describe('usableAccessToken', () => {
  const NOW = 1_800_000_000_000;

  it('returns the token while it has more than the skew left', () => {
    expect(usableAccessToken(serializeAccessToken(LIVE_TOKEN, 3600, NOW), NOW)).toBe(LIVE_TOKEN);
  });

  it('returns null once the token is expired, or inside the skew before expiry', () => {
    const raw = serializeAccessToken(LIVE_TOKEN, 3600, NOW);
    expect(usableAccessToken(raw, NOW + 3600_000)).toBeNull();
    expect(usableAccessToken(raw, NOW + 3600_000 - ACCESS_TOKEN_EXPIRY_SKEW_MS)).toBeNull();
    expect(usableAccessToken(raw, NOW + 3600_000 - ACCESS_TOKEN_EXPIRY_SKEW_MS - 1)).toBe(LIVE_TOKEN);
  });

  it('returns null for a missing or malformed value', () => {
    for (const raw of [null, undefined, '', 'not-json', '{}', '{"t":"x"}', '{"t":"","exp":9e15}', 'null', '5']) {
      expect(usableAccessToken(raw, NOW)).toBeNull();
    }
  });
});
