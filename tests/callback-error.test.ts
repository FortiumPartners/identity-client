import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';
import express from 'express';
import cookieParser from 'cookie-parser';

/**
 * identity#77 / identity-client#24: when Identity refuses a login it redirects
 * to /auth/callback?error=access_denied&state=... (RFC 6749 section 4.1.2.1).
 * The plugins used to turn every code-less callback into invalid_callback, so an
 * app could not tell a refusal from a broken callback and restarted the login.
 * Both plugins now forward a registered error code, but only when the returned
 * state matches a pending attempt of this browser.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { createIdentityRouter } from '../packages/express/src/plugin.js';
import { IdentityClient } from '../packages/core/src/identity-client.js';
import { sanitizeCallbackError, CALLBACK_ERROR_CODES } from '../packages/core/src/callback-error.js';

const ISSUER = 'https://identity.example.com';
const FRONTEND = 'https://app.test';
const COOKIE_SECRET = 'callback-error-test-cookie-secret-not-real';

const realFetch = global.fetch;

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

describe('sanitizeCallbackError', () => {
  const REGISTERED = [
    // RFC 6749 section 4.1.2.1
    'invalid_request',
    'unauthorized_client',
    'access_denied',
    'unsupported_response_type',
    'invalid_scope',
    'server_error',
    'temporarily_unavailable',
    // OIDC Core section 3.1.2.6
    'interaction_required',
    'login_required',
    'account_selection_required',
    'consent_required',
    'invalid_request_uri',
    'invalid_request_object',
    'request_not_supported',
    'request_uri_not_supported',
    'registration_not_supported',
  ];

  it.each(REGISTERED)('accepts %s', (code) => {
    expect(sanitizeCallbackError(code)).toBe(code);
  });

  it('accepts exactly the registered codes', () => {
    expect([...CALLBACK_ERROR_CODES].sort()).toEqual([...REGISTERED].sort());
  });

  it.each([
    ['an unknown code', 'bogus'],
    ['a different case', 'ACCESS_DENIED'],
    ['a padded code', ' access_denied'],
    ['a code with a suffix', 'access_denied<script>'],
    ['a description', 'The user denied the request'],
    ['an empty string', ''],
    ['an array', ['access_denied']],
    ['an object', { error: 'access_denied' }],
    ['a number', 403],
    ['null', null],
    ['undefined', undefined],
  ])('drops %s', (_label, raw) => {
    expect(sanitizeCallbackError(raw)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

interface Res {
  status: number;
  body: string;
  location?: string;
  setCookies: string[];
}

interface Harness {
  /** `cookie` is a raw `name=value` pair, as a browser would send it. */
  get(url: string, cookie?: string): Promise<Res>;
  close(): Promise<void>;
}

function pluginOpts() {
  return {
    issuer: ISSUER,
    clientId: 'talent',
    clientSecret: 'plugin-test-secret',
    callbackUrl: `${FRONTEND}/auth/callback`,
    frontendUrl: FRONTEND,
    jwtSecret: 'plugin-test-jwt-secret-not-real',
    sessionIssuer: 'talent',
  };
}

async function fastifyHarness(): Promise<Harness> {
  const app: FastifyInstance = fastify({ logger: false });
  await app.register(fastifyCookie, { secret: COOKIE_SECRET });
  await app.register(
    async (instance) => {
      await instance.register(identityPlugin, pluginOpts());
    },
    { prefix: '/auth' },
  );
  return {
    async get(url, cookie) {
      const res = await app.inject({ method: 'GET', url, headers: cookie ? { cookie } : {} });
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

async function expressHarness(): Promise<Harness> {
  const spies = [
    jest.spyOn(console, 'warn').mockImplementation(() => undefined),
    jest.spyOn(console, 'error').mockImplementation(() => undefined),
  ];
  const app = express();
  app.use(cookieParser(COOKIE_SECRET));
  app.use('/auth', createIdentityRouter(pluginOpts() as Parameters<typeof createIdentityRouter>[0]));
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    async get(url, cookie) {
      const res = await realFetch(`http://127.0.0.1:${port}${url}`, {
        redirect: 'manual',
        headers: cookie ? { cookie } : {},
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
        for (const spy of spies) spy.mockRestore();
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const HARNESSES: Array<[string, () => Promise<Harness>]> = [
  ['Fastify', fastifyHarness],
  ['Express', expressHarness],
];

/** The `oidc_state=...` pair a browser would send back after this response, if it set one. */
function stateCookiePair(res: Res): string | undefined {
  const line = res.setCookies.find((c) => c.startsWith('oidc_state='));
  const pair = line?.split(';')[0];
  return pair && pair !== 'oidc_state=' ? pair : undefined;
}

/**
 * The cookies a response set, minus the login guard (identity-client#25): an
 * untrusted callback changes no oidc_state cookie, but it does arm the guard.
 */
function withoutGuard(res: Res): string[] {
  return res.setCookies.filter((c) => !c.startsWith('login_guard='));
}

/** The pending `state` values stored in an oidc_state cookie pair. */
function storedStates(pair: string): string[] {
  let value = decodeURIComponent(pair.slice('oidc_state='.length));
  if (value.startsWith('s:')) value = value.slice(2); // cookie-parser's signed prefix
  const json = value.slice(0, value.lastIndexOf('.')); // drop the signature
  return (JSON.parse(json) as Array<{ state: string }>).map((s) => s.state);
}

describe.each(HARNESSES)('%s plugin: GET /auth/callback with an OAuth error response', (_name, build) => {
  let h: Harness;

  beforeEach(async () => {
    h = await build();
  });

  afterEach(async () => {
    await h.close();
    jest.restoreAllMocks();
    global.fetch = realFetch;
  });

  /** Start a login; returns the state Identity would echo and the browser's cookie. */
  async function login(existingCookie?: string): Promise<{ state: string; cookie: string }> {
    const res = await h.get('/auth/login', existingCookie);
    expect(res.status).toBe(302);
    const cookie = stateCookiePair(res) as string;
    const state = new URL(res.location as string).searchParams.get('state') as string;
    return { state, cookie };
  }

  it('forwards access_denied as /login?error=access_denied when the state matches', async () => {
    const { state, cookie } = await login();
    const res = await h.get(`/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`, cookie);
    expect(res.status).toBe(302);
    expect(res.location).toBe(`${FRONTEND}/login?error=access_denied`);
  });

  it.each([...CALLBACK_ERROR_CODES])('forwards the registered code %s', async (code) => {
    const { state, cookie } = await login();
    const res = await h.get(`/auth/callback?error=${code}&state=${encodeURIComponent(state)}`, cookie);
    expect(res.location).toBe(`${FRONTEND}/login?error=${code}`);
  });

  it('maps an unknown error value to invalid_callback, and never reflects it', async () => {
    const { state, cookie } = await login();
    for (const bad of ['bogus', 'ACCESS_DENIED', '<script>alert(1)</script>', 'access_denied%0d%0aSet-Cookie:x=1']) {
      const res = await h.get(`/auth/callback?error=${encodeURIComponent(bad)}&state=${encodeURIComponent(state)}`, cookie);
      expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expect(res.body).not.toContain('script');
    }
  });

  it('maps a repeated error parameter to invalid_callback', async () => {
    const { state, cookie } = await login();
    const res = await h.get(
      `/auth/callback?error=access_denied&error=login_required&state=${encodeURIComponent(state)}`,
      cookie,
    );
    expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
  });

  it('never reflects error_description or error_uri into the redirect or the body', async () => {
    const { state, cookie } = await login();
    const description = 'User-denied-the-authorization-request-zq7';
    const uri = 'https://evil.example/zq7-more-info';
    const res = await h.get(
      `/auth/callback?error=access_denied&error_description=${encodeURIComponent(description)}` +
        `&error_uri=${encodeURIComponent(uri)}&state=${encodeURIComponent(state)}`,
      cookie,
    );
    expect(res.location).toBe(`${FRONTEND}/login?error=access_denied`);
    expect(res.location).not.toContain('zq7');
    expect(res.body).not.toContain('zq7');
    expect(res.setCookies.join('\n')).not.toContain('zq7');
  });

  it('consumes the matching attempt and keeps the other in-flight attempt', async () => {
    const first = await login();
    const second = await login(first.cookie);
    // The second login appended to the first one's cookie.
    expect(storedStates(second.cookie)).toEqual([first.state, second.state]);

    const res = await h.get(`/auth/callback?error=access_denied&state=${encodeURIComponent(first.state)}`, second.cookie);
    expect(res.location).toBe(`${FRONTEND}/login?error=access_denied`);
    const remaining = stateCookiePair(res);
    expect(remaining).toBeDefined();
    expect(storedStates(remaining as string)).toEqual([second.state]);
  });

  it('clears oidc_state when the matching attempt was the only one', async () => {
    const { state, cookie } = await login();
    const res = await h.get(`/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`, cookie);
    const line = res.setCookies.find((c) => c.startsWith('oidc_state='));
    expect(line).toBeDefined();
    expect(stateCookiePair(res)).toBeUndefined();
  });

  describe('keeps the pre-existing invalid_callback when the state cannot be trusted', () => {
    it('error without a state', async () => {
      const { cookie } = await login();
      const res = await h.get('/auth/callback?error=access_denied', cookie);
      expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expect(withoutGuard(res)).toEqual([]);
    });

    it('error with a state that matches no pending attempt', async () => {
      const { cookie } = await login();
      const res = await h.get('/auth/callback?error=access_denied&state=does-not-exist', cookie);
      expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expect(withoutGuard(res)).toEqual([]);
    });

    it('error with a state but no state cookie', async () => {
      const { state } = await login();
      const res = await h.get(`/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`);
      expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expect(withoutGuard(res)).toEqual([]);
    });

    it('error with a state cookie whose signature is invalid', async () => {
      const { state, cookie } = await login();
      const forged = cookie.slice(0, -4) + 'AAAA';
      const res = await h.get(`/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`, forged);
      expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expect(withoutGuard(res)).toEqual([]);
    });

    it('a repeated state parameter', async () => {
      const { state, cookie } = await login();
      const res = await h.get(
        `/auth/callback?error=access_denied&state=${encodeURIComponent(state)}&state=other`,
        cookie,
      );
      expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
    });
  });

  it('does not take the error path when a code is present: the exchange still runs', async () => {
    const exchange = jest
      .spyOn(IdentityClient.prototype, 'exchangeCode')
      .mockRejectedValue(new Error('exchange attempted'));
    const { state, cookie } = await login();
    const res = await h.get(
      `/auth/callback?code=authcode&error=access_denied&state=${encodeURIComponent(state)}`,
      cookie,
    );
    expect(exchange).toHaveBeenCalledTimes(1);
    expect(res.location).toBe(`${FRONTEND}/login?error=callback_failed`);
  });

  it('a callback with neither code nor error is still invalid_callback', async () => {
    const { state, cookie } = await login();
    const res = await h.get(`/auth/callback?state=${encodeURIComponent(state)}`, cookie);
    expect(res.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
  });
});
