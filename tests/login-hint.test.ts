import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';
import express from 'express';
import cookieParser from 'cookie-parser';

/**
 * login_hint forwarding (#20): core's sanitizeLoginHint and
 * generateAuthorizationUrl options, and GET /auth/login on both plugins,
 * including the resolveLoginHint option.
 *
 * The plugin cases compare a login with a hint against the same login
 * without one, with crypto.getRandomValues made deterministic, so state,
 * nonce and PKCE are compared byte for byte rather than by shape.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { createIdentityRouter } from '../packages/express/src/plugin.js';
import { IdentityClient } from '../packages/core/src/identity-client.js';
import { sanitizeLoginHint, LOGIN_HINT_MAX_LENGTH } from '../packages/core/src/login-hint.js';

const ISSUER = 'https://identity.example.com';
const AUTHORIZE_ENDPOINT = `${ISSUER}/oidc/auth`;
const CALLBACK_URL = 'https://app.test/auth/callback';
const COOKIE_SECRET = 'login-hint-test-cookie-secret-not-real';

const realFetch = global.fetch;

// Distinctive enough that its absence from logs and cookies means something.
const HINT = 'ada.zq7@example.com';
const HINT_QUERY = encodeURIComponent(HINT);

/** An address of exactly `length` characters. */
function addressOfLength(length: number): string {
  const domain = '@example.com';
  return 'x'.repeat(length - domain.length) + domain;
}

/** Fill every random buffer with 0, 1, 2, … so each login draws the same values. */
function deterministicRandom() {
  return jest.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
    const bytes = array as unknown as Uint8Array;
    for (let i = 0; i < bytes.length; i++) bytes[i] = i;
    return array;
  });
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

describe('sanitizeLoginHint', () => {
  it.each([
    ['an email address', HINT, HINT],
    ['surrounding spaces, trimmed', `  ${HINT} `, HINT],
    ['one character', 'a', 'a'],
    ['254 characters', addressOfLength(254), addressOfLength(254)],
    ['254 characters once trimmed', ` ${addressOfLength(254)} `, addressOfLength(254)],
  ])('accepts %s', (_label, raw, expected) => {
    expect(sanitizeLoginHint(raw)).toBe(expected);
  });

  it.each([
    ['an empty string', ''],
    ['only whitespace', '   '],
    ['255 characters', addressOfLength(255)],
    ['a newline inside', 'ada\n@example.com'],
    ['a trailing newline', `${HINT}\n`],
    ['a tab', `${HINT}\t`],
    ['a NUL', 'ada\u0000@example.com'],
    ['DEL', 'ada\u007f@example.com'],
    ['a C1 control', 'ada\u0085@example.com'],
    ['a number', 42],
    ['an array', [HINT]],
    ['an object', { hint: HINT }],
    ['null', null],
    ['undefined', undefined],
  ])('drops %s', (_label, raw) => {
    expect(sanitizeLoginHint(raw)).toBeUndefined();
  });

  it('caps at the maximum email length', () => {
    expect(LOGIN_HINT_MAX_LENGTH).toBe(254);
  });
});

describe('IdentityClient.generateAuthorizationUrl options', () => {
  const client = new IdentityClient({ issuer: ISSUER, clientId: 'gateway', clientSecret: 'core-test-secret' });
  let random: ReturnType<typeof deterministicRandom>;

  beforeEach(() => {
    random = deterministicRandom();
  });

  afterEach(() => {
    random.mockRestore();
  });

  it('without opts builds the pre-1.5.0 URL: the base parameters only, in order', async () => {
    const { url, state } = await client.generateAuthorizationUrl(CALLBACK_URL);
    const parsed = new URL(url);
    expect(`${parsed.origin}${parsed.pathname}`).toBe(AUTHORIZE_ENDPOINT);
    expect([...parsed.searchParams.keys()]).toEqual([
      'response_type',
      'client_id',
      'redirect_uri',
      'scope',
      'state',
      'nonce',
      'code_challenge',
      'code_challenge_method',
    ]);
    expect(parsed.searchParams.get('state')).toBe(state.state);
    expect(parsed.searchParams.get('nonce')).toBe(state.nonce);
    expect(parsed.searchParams.get('code_challenge')).toBe(
      createHash('sha256').update(state.codeVerifier).digest('base64url'),
    );
  });

  it('with empty opts, or only invalid values, builds exactly the URL without opts', async () => {
    const { url: bare } = await client.generateAuthorizationUrl(CALLBACK_URL);
    const { url: empty } = await client.generateAuthorizationUrl(CALLBACK_URL, {});
    const { url: invalid } = await client.generateAuthorizationUrl(CALLBACK_URL, {
      loginHint: 'ada\n@example.com',
      prompt: 'bogus',
    });
    expect(empty).toBe(bare);
    expect(invalid).toBe(bare);
  });

  it('appends the trimmed login_hint after the base parameters', async () => {
    const { url: bare } = await client.generateAuthorizationUrl(CALLBACK_URL);
    const { url } = await client.generateAuthorizationUrl(CALLBACK_URL, { loginHint: `  ${HINT} ` });
    expect(url).toBe(`${bare}&login_hint=${HINT_QUERY}`);
    expect(new URL(url).searchParams.get('login_hint')).toBe(HINT);
  });

  it('appends an allowed prompt, then the login_hint', async () => {
    const { url: bare } = await client.generateAuthorizationUrl(CALLBACK_URL);
    const { url } = await client.generateAuthorizationUrl(CALLBACK_URL, { prompt: 'select_account', loginHint: HINT });
    expect(url).toBe(`${bare}&prompt=select_account&login_hint=${HINT_QUERY}`);
  });

  it('builds the same prompt URL the plugins built before 1.5.0', async () => {
    const { url: bare } = await client.generateAuthorizationUrl(CALLBACK_URL);
    const before = new URL(bare);
    before.searchParams.set('prompt', 'login');
    const { url } = await client.generateAuthorizationUrl(CALLBACK_URL, { prompt: 'login' });
    expect(url).toBe(before.toString());
  });
});

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

type ResolveLoginHint = (request: unknown) => string | undefined | Promise<string | undefined>;

interface LoginResponse {
  status: number;
  body: string;
  location?: string;
  setCookies: string[];
}

interface Harness {
  get(url: string): Promise<LoginResponse>;
  /** Every log line the plugin wrote, joined. */
  logs(): string;
  close(): Promise<void>;
}

function pluginOpts(resolveLoginHint?: ResolveLoginHint) {
  return {
    issuer: ISSUER,
    clientId: 'gateway',
    clientSecret: 'plugin-test-secret',
    callbackUrl: CALLBACK_URL,
    frontendUrl: 'https://app.test',
    jwtSecret: 'plugin-test-jwt-secret-not-real',
    sessionIssuer: 'gateway',
    ...(resolveLoginHint ? { resolveLoginHint } : {}),
  };
}

async function fastifyHarness(resolveLoginHint?: ResolveLoginHint): Promise<Harness> {
  const lines: string[] = [];
  // Request logging is off so the capture holds only what the plugin logs:
  // Fastify's own request log records the URL, query string included.
  const app: FastifyInstance = fastify({
    logger: { level: 'debug', stream: { write: (line: string) => lines.push(line) } },
    disableRequestLogging: true,
  });
  await app.register(fastifyCookie, { secret: COOKIE_SECRET });
  await app.register(
    async (instance) => {
      await instance.register(identityPlugin, pluginOpts(resolveLoginHint));
    },
    { prefix: '/auth' },
  );
  return {
    async get(url) {
      const res = await app.inject({ method: 'GET', url });
      const raw = res.headers['set-cookie'];
      return {
        status: res.statusCode,
        body: res.body,
        location: res.headers.location as string | undefined,
        setCookies: Array.isArray(raw) ? raw : raw ? [String(raw)] : [],
      };
    },
    logs: () => lines.join(''),
    close: () => app.close(),
  };
}

async function expressHarness(resolveLoginHint?: ResolveLoginHint): Promise<Harness> {
  const lines: string[] = [];
  const capture = (...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  };
  const spies = [
    jest.spyOn(console, 'debug').mockImplementation(capture),
    jest.spyOn(console, 'log').mockImplementation(capture),
    jest.spyOn(console, 'warn').mockImplementation(capture),
    jest.spyOn(console, 'error').mockImplementation(capture),
  ];
  const app = express();
  app.use(cookieParser(COOKIE_SECRET));
  app.use('/auth', createIdentityRouter(pluginOpts(resolveLoginHint) as Parameters<typeof createIdentityRouter>[0]));
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    async get(url) {
      const res = await realFetch(`http://127.0.0.1:${port}${url}`, { redirect: 'manual' });
      return {
        status: res.status,
        body: await res.text(),
        location: res.headers.get('location') ?? undefined,
        setCookies: res.headers.getSetCookie(),
      };
    },
    logs: () => lines.join('\n'),
    close: () =>
      new Promise<void>((resolve) => {
        for (const spy of spies) spy.mockRestore();
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** The pending OIDC states in the oidc_state cookie, with the timestamp removed. */
function pendingStates(res: LoginResponse): Array<Record<string, unknown>> {
  const line = res.setCookies.find((c) => c.startsWith('oidc_state='));
  if (!line) throw new Error('no oidc_state cookie set');
  let value = decodeURIComponent(line.split(';')[0].slice('oidc_state='.length));
  if (value.startsWith('s:')) value = value.slice(2); // cookie-parser's signed prefix
  const json = value.slice(0, value.lastIndexOf('.')); // drop the signature
  return (JSON.parse(json) as Array<Record<string, unknown>>).map(({ ts: _ts, ...rest }) => rest);
}

/** The redirect's query parameters, asserting it goes to Identity's authorize endpoint. */
function authorizeParams(res: LoginResponse): URLSearchParams {
  expect(res.status).toBe(302);
  const url = new URL(res.location as string);
  expect(`${url.origin}${url.pathname}`).toBe(AUTHORIZE_ENDPOINT);
  return url.searchParams;
}

const HARNESSES: Array<[string, (resolveLoginHint?: ResolveLoginHint) => Promise<Harness>]> = [
  ['Fastify', fastifyHarness],
  ['Express', expressHarness],
];

describe.each(HARNESSES)('%s plugin: GET /auth/login forwards login_hint', (_name, build) => {
  let h: Harness | undefined;
  let random: ReturnType<typeof deterministicRandom>;

  beforeEach(() => {
    random = deterministicRandom();
  });

  afterEach(async () => {
    await h?.close();
    h = undefined;
    random.mockRestore();
  });

  it('acceptance: forwards login_hint and leaves returnTo, state, nonce and PKCE unchanged', async () => {
    h = await build();
    const without = await h.get('/auth/login?returnTo=%2Fintake%2Fverify');
    const withHint = await h.get('/auth/login?login_hint=ada%40example.com&returnTo=%2Fintake%2Fverify');

    const params = authorizeParams(withHint);
    expect(params.get('login_hint')).toBe('ada@example.com');
    expect(withHint.location).toBe(`${without.location}&login_hint=ada%40example.com`);

    // The same parameter set, less login_hint, with the same values.
    const withoutParams = authorizeParams(without);
    params.delete('login_hint');
    expect([...params.entries()]).toEqual([...withoutParams.entries()]);

    // The pending state (state, nonce, PKCE verifier, returnTo) is identical,
    // and it is the state the redirect carries.
    const states = pendingStates(withHint);
    expect(states).toEqual(pendingStates(without));
    expect(states).toHaveLength(1);
    expect(states[0].state).toBe(params.get('state'));
    expect(params.get('code_challenge')).toBe(
      createHash('sha256').update(states[0].codeVerifier as string).digest('base64url'),
    );
    if (_name === 'Fastify') expect(states[0].returnTo).toBe('/intake/verify');
  });

  it('leaves prompt unchanged, and never reflects or logs the hint', async () => {
    h = await build();
    const without = await h.get('/auth/login?prompt=login');
    const withHint = await h.get(`/auth/login?prompt=login&login_hint=${HINT_QUERY}`);

    expect(authorizeParams(without).get('prompt')).toBe('login');
    expect(withHint.location).toBe(`${without.location}&login_hint=${HINT_QUERY}`);
    expect(pendingStates(withHint)).toEqual(pendingStates(without));

    // Express's redirect body repeats the Location URL; nothing else may carry the hint.
    const body = withHint.body.replace(withHint.location as string, '');
    const reflected = withHint.setCookies.join('\n') + body + h.logs();
    expect(reflected).not.toContain('zq7');
  });

  it('forwards a hint trimmed of surrounding whitespace', async () => {
    h = await build();
    const res = await h.get(`/auth/login?login_hint=${encodeURIComponent(`  ${HINT} `)}`);
    expect(authorizeParams(res).get('login_hint')).toBe(HINT);
  });

  it('forwards a 254-character hint', async () => {
    h = await build();
    const res = await h.get(`/auth/login?login_hint=${encodeURIComponent(addressOfLength(254))}`);
    expect(authorizeParams(res).get('login_hint')).toBe(addressOfLength(254));
  });

  const invalid: Array<[string, string]> = [
    ['empty', 'login_hint='],
    ['whitespace only', 'login_hint=%20%20'],
    ['255 characters', `login_hint=${encodeURIComponent(addressOfLength(255).replace('xxx', 'zq7'))}`],
    ['containing \\n', `login_hint=${encodeURIComponent('ada.zq7\n@example.com')}`],
    ['containing \\u0000', `login_hint=${encodeURIComponent('ada.zq7\u0000@example.com')}`],
    ['repeated (an array)', `login_hint=${HINT_QUERY}&login_hint=${encodeURIComponent('b.zq7@example.com')}`],
  ];

  it.each(invalid)('drops an invalid hint (%s), logs only that it was dropped, and still redirects', async (_label, query) => {
    h = await build();
    const without = await h.get('/auth/login?returnTo=%2Fintake%2Fverify');
    const res = await h.get(`/auth/login?${query}&returnTo=%2Fintake%2Fverify`);

    const params = authorizeParams(res);
    expect(params.has('login_hint')).toBe(false);
    expect(res.location).toBe(without.location);
    expect(pendingStates(res)).toEqual(pendingStates(without));

    expect(h.logs()).toContain('login_hint rejected');
    expect(h.logs()).not.toContain('zq7');
  });

  if (_name === 'Express') {
    it('drops a hint Express parses into an object', async () => {
      h = await build();
      const res = await h.get('/auth/login?login_hint%5Bzq7%5D=1');
      expect(authorizeParams(res).has('login_hint')).toBe(false);
      expect(h.logs()).toContain('login_hint rejected');
    });
  }

  describe('resolveLoginHint', () => {
    it('is used when the query has no login_hint', async () => {
      const resolve = jest.fn<ResolveLoginHint>(async () => 'grace@example.com');
      h = await build(resolve);
      const res = await h.get('/auth/login?returnTo=%2Fintake%2Fverify');
      expect(authorizeParams(res).get('login_hint')).toBe('grace@example.com');
      expect(resolve).toHaveBeenCalledTimes(1);
    });

    it('may return synchronously', async () => {
      h = await build(() => 'grace@example.com');
      const res = await h.get('/auth/login');
      expect(authorizeParams(res).get('login_hint')).toBe('grace@example.com');
    });

    it('loses to a valid query hint, and is not called', async () => {
      const resolve = jest.fn<ResolveLoginHint>(async () => 'grace@example.com');
      h = await build(resolve);
      const res = await h.get(`/auth/login?login_hint=${HINT_QUERY}`);
      expect(authorizeParams(res).get('login_hint')).toBe(HINT);
      expect(resolve).not.toHaveBeenCalled();
    });

    it('is used when the query hint is invalid', async () => {
      const resolve = jest.fn<ResolveLoginHint>(async () => 'grace@example.com');
      h = await build(resolve);
      const res = await h.get('/auth/login?login_hint=');
      expect(authorizeParams(res).get('login_hint')).toBe('grace@example.com');
      expect(resolve).toHaveBeenCalledTimes(1);
    });

    it.each([
      ['throws', () => {
        throw new Error('resolver exploded');
      }],
      ['rejects', async () => {
        throw new Error('resolver exploded');
      }],
    ] as Array<[string, ResolveLoginHint]>)('%s: logs at warn and still redirects, with no hint', async (_label, resolver) => {
      h = await build(resolver);
      const without = await h.get('/auth/login?returnTo=%2Fintake%2Fverify');
      const res = await h.get('/auth/login?returnTo=%2Fintake%2Fverify');

      expect(authorizeParams(res).has('login_hint')).toBe(false);
      expect(res.location).toBe(without.location);
      expect(pendingStates(res)).toEqual(pendingStates(without));

      const warnings = h
        .logs()
        .split('\n')
        .filter((l) => l.includes('resolveLoginHint threw'));
      expect(warnings.length).toBeGreaterThanOrEqual(1);
      // pino writes level 40 for warn; the Express plugin writes level "warn".
      for (const line of warnings) expect(line).toMatch(/"level":(40|"warn")/);
    });

    it('drops an invalid resolved hint, without logging it', async () => {
      h = await build(async () => 'ada.zq7\u0000@example.com');
      const res = await h.get('/auth/login');
      expect(authorizeParams(res).has('login_hint')).toBe(false);
      expect(h.logs()).toContain('login_hint rejected');
      expect(h.logs()).not.toContain('zq7');
    });

    it('returning undefined gives no hint and logs nothing about it', async () => {
      h = await build(async () => undefined);
      const res = await h.get('/auth/login');
      expect(authorizeParams(res).has('login_hint')).toBe(false);
      expect(h.logs()).not.toContain('login_hint');
    });
  });
});
