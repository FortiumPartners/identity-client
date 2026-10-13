import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import fastify, { type FastifyInstance } from 'fastify';
import fastifyCookie from '@fastify/cookie';
import express from 'express';
import cookieParser from 'cookie-parser';

/**
 * identity-client#25: after a callback that ended in an error, /login must not
 * start another authorization request for a short window, so an app whose
 * /login restarts the flow cannot loop between the app and Identity. The guard
 * is its own signed cookie. prompt=login / select_account (OIDC Core section
 * 3.1.2.1) and a successful sign-in end it.
 *
 * The plugin tests drive a whole browser: a cookie jar, the redirect chain, a
 * stub app /login page, and a stub Identity that refuses every authorization
 * request. They count the authorization redirects.
 */

import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { createIdentityRouter } from '../packages/express/src/plugin.js';
import { IdentityClient } from '../packages/core/src/identity-client.js';
import type { FortiumClaims } from '../packages/core/src/types.js';
import {
  serializeLoginGuard,
  activeLoginGuard,
  isExplicitLoginPrompt,
  loginGuardRetryUrl,
  renderLoginGuardPage,
  LOGIN_GUARD_DEFAULT_SECONDS,
  LOGIN_GUARD_PAGE_HEADERS,
} from '../packages/core/src/login-guard.js';
import { CALLBACK_ERROR_CODES } from '../packages/core/src/callback-error.js';

const ISSUER = 'https://identity.example.com';
const FRONTEND = 'https://app.test';
const COOKIE_SECRET = 'login-guard-test-cookie-secret-not-real';
const T0 = 1_800_000_000_000;

const realFetch = global.fetch;

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

describe('login guard (core)', () => {
  it('defaults to 30 seconds', () => {
    expect(LOGIN_GUARD_DEFAULT_SECONDS).toBe(30);
  });

  it('is active inside the window and over exactly at the window', () => {
    const raw = serializeLoginGuard('access_denied', T0);
    expect(activeLoginGuard(raw, 30, T0)).toBe('access_denied');
    expect(activeLoginGuard(raw, 30, T0 + 29_999)).toBe('access_denied');
    expect(activeLoginGuard(raw, 30, T0 + 30_000)).toBeUndefined();
    expect(activeLoginGuard(raw, 30, T0 + 3_600_000)).toBeUndefined();
  });

  it('follows the configured window', () => {
    const raw = serializeLoginGuard('access_denied', T0);
    expect(activeLoginGuard(raw, 5, T0 + 4_999)).toBe('access_denied');
    expect(activeLoginGuard(raw, 5, T0 + 5_000)).toBeUndefined();
    expect(activeLoginGuard(raw, 0, T0)).toBeUndefined();
  });

  it.each([...CALLBACK_ERROR_CODES, 'invalid_callback'])('round-trips %s', (code) => {
    expect(activeLoginGuard(serializeLoginGuard(code, T0), 30, T0)).toBe(code);
  });

  it.each([
    ['an unknown code', 'bogus'],
    ['a markup string', '<script>alert(1)</script>'],
    ['a header-splitting string', 'access_denied\r\nSet-Cookie: x=1'],
    ['an array', ['access_denied']],
    ['undefined', undefined],
  ])('stores invalid_callback for %s, never the raw value', (_label, raw) => {
    const stored = serializeLoginGuard(raw, T0);
    expect(JSON.parse(stored)).toEqual({ error: 'invalid_callback', ts: T0 });
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['an empty string', ''],
    ['not JSON', 'access_denied'],
    ['a JSON string', '"access_denied"'],
    ['a JSON array', '[]'],
    ['no error', JSON.stringify({ ts: T0 })],
    ['an unregistered error', JSON.stringify({ error: 'bogus', ts: T0 })],
    ['a non-string error', JSON.stringify({ error: 1, ts: T0 })],
    ['no timestamp', JSON.stringify({ error: 'access_denied' })],
    ['a string timestamp', JSON.stringify({ error: 'access_denied', ts: String(T0) })],
  ])('ignores a guard that is %s', (_label, raw) => {
    expect(activeLoginGuard(raw as string | null | undefined, 30, T0)).toBeUndefined();
  });

  it.each([
    ['login', true],
    ['select_account', true],
    ['consent', false],
    ['none', false],
    ['', false],
    ['login consent', false],
    ['LOGIN', false],
    [undefined, false],
    [['login'], false],
  ])('isExplicitLoginPrompt(%j) is %s', (prompt, expected) => {
    expect(isExplicitLoginPrompt(prompt)).toBe(expected);
  });
});

describe('login guard page (core)', () => {
  const RETRY = 'https://app.test/auth/login?prompt=login';

  it('has the headers of a terminal, uncacheable page', () => {
    expect(LOGIN_GUARD_PAGE_HEADERS).toEqual({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
    });
  });

  it('is a plain page with a lang, a title, the code and exactly one link', () => {
    const html = renderLoginGuardPage('access_denied', RETRY);
    expect(html).toMatch(/^<!DOCTYPE html>/);
    expect(html).toContain('<html lang="en">');
    expect(html).toMatch(/<title>[^<]+<\/title>/);
    expect(html).toContain('<code>access_denied</code>');
    expect(html.match(/<a /g)).toHaveLength(1);
    expect(html).toContain(`<a href="${RETRY}">Try again</a>`);
  });

  it('carries no script, no style and no external resource', () => {
    const html = renderLoginGuardPage('access_denied', RETRY);
    for (const banned of ['<script', 'style=', '<style', '<link', '<img', '<iframe', '<form', 'onclick', 'src=']) {
      expect(html.toLowerCase()).not.toContain(banned);
    }
  });

  it('escapes the code and the link', () => {
    const html = renderLoginGuardPage('<script>alert(1)</script>"\'&', 'https://app.test/a?x="><script>&y=1');
    expect(html).not.toContain('<script');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;');
    expect(html).toContain('href="https://app.test/a?x=&quot;&gt;&lt;script&gt;&amp;y=1"');
  });

  describe('loginGuardRetryUrl', () => {
    it('is the sibling login route of the callback URL, with prompt=login', () => {
      expect(loginGuardRetryUrl('https://app.test/auth/callback')).toBe('https://app.test/auth/login?prompt=login');
      expect(loginGuardRetryUrl('https://app.test/api/v2/auth/callback')).toBe(
        'https://app.test/api/v2/auth/login?prompt=login',
      );
    });

    it('keeps an already validated returnTo, percent-encoded', () => {
      expect(loginGuardRetryUrl('https://app.test/auth/callback', '/deals?id=1&x=2')).toBe(
        'https://app.test/auth/login?prompt=login&returnTo=%2Fdeals%3Fid%3D1%26x%3D2',
      );
    });

    it('drops any query on the callback URL', () => {
      expect(loginGuardRetryUrl('https://app.test/auth/callback?a=1')).toBe('https://app.test/auth/login?prompt=login');
    });
  });
});

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

interface Res {
  status: number;
  body: string;
  location?: string;
  contentType?: string;
  cacheControl?: string;
  referrerPolicy?: string;
  setCookies: string[];
}

interface Harness {
  /** `cookie` is a raw `name=value; name=value` header, as a browser would send it. */
  get(url: string, cookie?: string): Promise<Res>;
  close(): Promise<void>;
}

function pluginOpts(extra: Record<string, unknown> = {}) {
  return {
    issuer: ISSUER,
    clientId: 'talent',
    clientSecret: 'plugin-test-secret',
    callbackUrl: `${FRONTEND}/auth/callback`,
    frontendUrl: FRONTEND,
    jwtSecret: 'plugin-test-jwt-secret-not-real',
    sessionIssuer: 'talent',
    ...extra,
  };
}

async function fastifyHarness(extra: Record<string, unknown> = {}): Promise<Harness> {
  const app: FastifyInstance = fastify({ logger: false });
  await app.register(fastifyCookie, { secret: COOKIE_SECRET });
  await app.register(
    async (instance) => {
      await instance.register(identityPlugin, pluginOpts(extra));
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
        contentType: res.headers['content-type'] as string | undefined,
        cacheControl: res.headers['cache-control'] as string | undefined,
        referrerPolicy: res.headers['referrer-policy'] as string | undefined,
        setCookies: Array.isArray(raw) ? raw : raw ? [String(raw)] : [],
      };
    },
    close: () => app.close(),
  };
}

async function expressHarness(extra: Record<string, unknown> = {}): Promise<Harness> {
  const spies = [
    jest.spyOn(console, 'warn').mockImplementation(() => undefined),
    jest.spyOn(console, 'error').mockImplementation(() => undefined),
  ];
  const app = express();
  app.use(cookieParser(COOKIE_SECRET));
  app.use('/auth', createIdentityRouter(pluginOpts(extra) as Parameters<typeof createIdentityRouter>[0]));
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
        contentType: res.headers.get('content-type') ?? undefined,
        cacheControl: res.headers.get('cache-control') ?? undefined,
        referrerPolicy: res.headers.get('referrer-policy') ?? undefined,
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

const HARNESSES: Array<[string, (extra?: Record<string, unknown>) => Promise<Harness>]> = [
  ['Fastify', fastifyHarness],
  ['Express', expressHarness],
];

/** Only the Fastify plugin accepts `?returnTo=` on /login. */
const SUPPORTS_RETURN_TO: Record<string, boolean> = { Fastify: true, Express: false };

/** The guard's terminal page for `code`: 200, no redirect, the code shown. */
function expectGuardPage(res: Res, code: string): void {
  expect(res.status).toBe(200);
  expect(res.location).toBeUndefined();
  expect(res.contentType).toBe('text/html; charset=utf-8');
  expect(res.cacheControl).toBe('no-store');
  expect(res.referrerPolicy).toBe('no-referrer');
  expect(res.body).toContain(`<code>${code}</code>`);
}

/** The "Try again" href of a guard page, HTML-unescaped. */
function retryHref(res: Res): string {
  const match = /<a href="([^"]*)">Try again<\/a>/.exec(res.body);
  expect(match).not.toBeNull();
  return (match as RegExpExecArray)[1].replace(/&amp;/g, '&');
}

/** True when the response sends the browser to Identity's authorization endpoint. */
function toIdentity(res: Res): boolean {
  return res.status === 302 && new URL(res.location as string).origin === new URL(ISSUER).origin;
}

interface Trace {
  hops: string[];
  /** The last plugin response, when the chain ended on one. */
  last?: Res;
  /** Requests that reached Identity's authorization endpoint. */
  authorizationRedirects: number;
  /** 'page': the chain ended on a page. 'identity': it stopped at Identity. 'cap': it was still redirecting. */
  end: 'page' | 'identity' | 'cap';
}

const HOP_CAP = 30;

/**
 * A browser with a cookie jar that follows redirects between three parties: the
 * plugin (anything under /auth), the app's own /login page, and Identity.
 *
 * The app's /login page is either `compliant` (renders a page when it carries
 * `error`, as the 1.6.0 README asks) or `naive` (always sends the browser to
 * /auth/login, which is what looped Talent). Identity either `refuses` every
 * authorization request, redirecting back to /callback with access_denied and the
 * request's own state, or leaves the user at its sign-in page.
 */
class Browser {
  readonly jar = new Map<string, string>();

  constructor(
    private readonly h: Harness,
    private readonly app: 'compliant' | 'naive' = 'compliant',
    private readonly identityRefuses = true,
  ) {}

  cookieHeader(): string | undefined {
    const pairs = [...this.jar].map(([name, value]) => `${name}=${value}`);
    return pairs.length ? pairs.join('; ') : undefined;
  }

  private absorb(setCookies: string[]): void {
    for (const line of setCookies) {
      const [pair, ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      const lower = attrs.map((a) => a.trim().toLowerCase());
      const expires = lower.find((a) => a.startsWith('expires='));
      const removed =
        value === '' ||
        lower.includes('max-age=0') ||
        (expires !== undefined && Date.parse(expires.slice('expires='.length)) < 86_400_000);
      if (removed) this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  /** One request to the plugin, with this browser's cookies. */
  async hit(path: string): Promise<Res> {
    const res = await this.h.get(path, this.cookieHeader());
    this.absorb(res.setCookies);
    return res;
  }

  /** Navigate to `url` and follow every redirect. */
  async visit(url: string): Promise<Trace> {
    const trace: Trace = { hops: [], authorizationRedirects: 0, end: 'cap' };
    let current = url;
    for (let hop = 0; hop < HOP_CAP; hop++) {
      trace.hops.push(current);
      const u = new URL(current);
      if (u.origin === new URL(ISSUER).origin) {
        trace.authorizationRedirects++;
        if (!this.identityRefuses) return { ...trace, end: 'identity' };
        const state = u.searchParams.get('state') as string;
        const redirectUri = u.searchParams.get('redirect_uri') as string;
        current = `${redirectUri}?error=access_denied&state=${encodeURIComponent(state)}`;
        continue;
      }
      if (u.pathname.startsWith('/auth/')) {
        const res = await this.hit(u.pathname + u.search);
        if (!res.location) return { ...trace, end: 'page', last: res };
        current = new URL(res.location, FRONTEND).toString();
        continue;
      }
      // The app's own /login page.
      if (this.app === 'naive' || !u.searchParams.has('error')) {
        current = `${FRONTEND}/auth/login`;
        continue;
      }
      return { ...trace, end: 'page' };
    }
    return trace;
  }
}

/** The set-cookie line for `name`, if the response set (or cleared) it. */
function cookieLine(res: Res, name: string): string | undefined {
  return res.setCookies.find((c) => c.startsWith(`${name}=`));
}

describe.each(HARNESSES)('%s plugin: login guard', (_name, build) => {
  let h: Harness;
  let now: number;

  beforeEach(async () => {
    now = T0;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    h = await build();
  });

  afterEach(async () => {
    await h.close();
    jest.restoreAllMocks();
    global.fetch = realFetch;
  });

  it('control: with no earlier failure, the chain reaches the authorization endpoint', async () => {
    const browser = new Browser(h, 'compliant', false);
    const trace = await browser.visit(`${FRONTEND}/login`);
    expect(trace.authorizationRedirects).toBe(1);
    expect(trace.end).toBe('identity');
  });

  describe('a refused callback followed by an immediate login', () => {
    it('does not reach the authorization endpoint, and ends on the app error page', async () => {
      const browser = new Browser(h, 'compliant');

      // First attempt: reaches Identity once, Identity refuses, the app shows the refusal.
      const first = await browser.visit(`${FRONTEND}/login`);
      expect(first.authorizationRedirects).toBe(1);
      expect(first.end).toBe('page');
      expect(first.hops.at(-1)).toBe(`${FRONTEND}/login?error=access_denied`);
      expect(browser.jar.has('login_guard')).toBe(true);

      // Immediate second attempt: the plugin answers /auth/login with its own page.
      const second = await browser.visit(`${FRONTEND}/login`);
      expect(second.authorizationRedirects).toBe(0);
      expect(second.end).toBe('page');
      expect(second.hops).toEqual([`${FRONTEND}/login`, `${FRONTEND}/auth/login`]);
      expectGuardPage(second.last as Res, 'access_denied');
    });

    it('answers the login with a page, not a redirect to the app or back to the plugin', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      const res = await browser.hit('/auth/login');
      expectGuardPage(res, 'access_denied');
    });

    it('ends the chain on the plugin page when the app /login restarts the flow on every error', async () => {
      const browser = new Browser(h, 'naive');
      const trace = await browser.visit(`${FRONTEND}/login`);
      // app /login -> /auth/login -> Identity (refuses) -> /auth/callback ->
      // app /login?error -> /auth/login -> the plugin's page. Six hops, one
      // authorization redirect, and the last response has no Location.
      expect(trace.hops).toHaveLength(6);
      expect(trace.hops[1]).toBe(`${FRONTEND}/auth/login`);
      expect(trace.hops[4]).toBe(`${FRONTEND}/login?error=access_denied`);
      expect(trace.hops[5]).toBe(`${FRONTEND}/auth/login`);
      expect(trace.authorizationRedirects).toBe(1);
      expect(trace.end).toBe('page');
      expectGuardPage(trace.last as Res, 'access_denied');
    });

    it('the Try again link goes through to the authorization endpoint with prompt=login', async () => {
      const refusing = new Browser(h, 'naive');
      const refused = await refusing.visit(`${FRONTEND}/login`);
      const href = retryHref(refused.last as Res);
      expect(href).toBe(`${FRONTEND}/auth/login?prompt=login`);

      // The user clicks it (Identity now waits at its sign-in page).
      const clicking = new Browser(h, 'naive', false);
      clicking.jar.set('login_guard', refusing.jar.get('login_guard') as string);
      const trace = await clicking.visit(href);
      expect(trace.end).toBe('identity');
      expect(trace.authorizationRedirects).toBe(1);
      expect(new URL(trace.hops.at(-1) as string).searchParams.get('prompt')).toBe('login');
      expect(clicking.jar.has('login_guard')).toBe(false);
    });

    it('builds the link from the plugin options, not from request input', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      const hostile = await h.get(
        '/auth/login?x=%22%3E%3Cscript%3E&error=%3Cscript%3E&prompt=consent&redirect_uri=https://evil.example',
        browser.cookieHeader(),
      );
      expectGuardPage(hostile, 'access_denied');
      expect(retryHref(hostile)).toBe(`${FRONTEND}/auth/login?prompt=login`);
      expect(hostile.body).not.toContain('evil');
      expect(hostile.body).not.toContain('<script');
    });

    it('keeps a valid returnTo on the link only where the plugin supports it, and drops an invalid one', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      const valid = await h.get('/auth/login?returnTo=%2Fdeals%2F7', browser.cookieHeader());
      const invalid = await h.get('/auth/login?returnTo=%2F%2Fevil.example', browser.cookieHeader());
      if (SUPPORTS_RETURN_TO[_name]) {
        expect(retryHref(valid)).toBe(`${FRONTEND}/auth/login?prompt=login&returnTo=%2Fdeals%2F7`);
      } else {
        expect(retryHref(valid)).toBe(`${FRONTEND}/auth/login?prompt=login`);
      }
      expect(retryHref(invalid)).toBe(`${FRONTEND}/auth/login?prompt=login`);
    });

    it('the page has no script, no style and no external resource', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      const res = await browser.hit('/auth/login');
      for (const banned of ['<script', 'style=', '<style', '<link', '<img', '<iframe', 'src=']) {
        expect(res.body.toLowerCase()).not.toContain(banned);
      }
    });

    it('a forged or tampered cookie yields no page', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      const good = browser.jar.get('login_guard') as string;
      const forged = encodeURIComponent(serializeLoginGuard('access_denied', T0));
      for (const cookie of [`login_guard=${forged}`, `login_guard=${good.slice(0, -4)}AAAA`]) {
        const res = await h.get('/auth/login', cookie);
        expect(toIdentity(res)).toBe(true);
        expect(res.body).not.toContain('Sign-in did not complete');
      }
    });

    it('counts: N immediate retries produce zero further authorization redirects', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      let total = 0;
      for (let i = 0; i < 10; i++) total += (await browser.visit(`${FRONTEND}/auth/login`)).authorizationRedirects;
      expect(total).toBe(0);
    });

    it('arms the guard when the refusal also carries other in-flight attempts', async () => {
      const browser = new Browser(h, 'compliant', false);
      await browser.visit(`${FRONTEND}/auth/login`);
      await browser.visit(`${FRONTEND}/auth/login`); // second pending attempt, no guard yet
      const state = /"state":"([^"]+)"/.exec(decodeURIComponent(browser.jar.get('oidc_state') as string))?.[1] as string;
      const res = await browser.hit(`/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`);
      expect(res.location).toBe(`${FRONTEND}/login?error=access_denied`);
      expectGuardPage(await browser.hit('/auth/login'), 'access_denied');
    });
  });

  describe('an invalid_callback with no flow cookie', () => {
    it.each([
      ['an error with a state and no cookie', '/auth/callback?error=access_denied&state=gone'],
      ['no code, no error', '/auth/callback?state=gone'],
      ['no parameters', '/auth/callback'],
    ])('%s: the next login is not sent to Identity', async (_label, callback) => {
      const browser = new Browser(h, 'compliant');
      expect(browser.jar.has('oidc_state')).toBe(false);

      const refused = await browser.hit(callback);
      expect(refused.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expect(cookieLine(refused, 'login_guard')).toBeDefined();

      const trace = await browser.visit(`${FRONTEND}/login`);
      expect(trace.authorizationRedirects).toBe(0);
      expect(trace.end).toBe('page');
      expectGuardPage(trace.last as Res, 'invalid_callback');
    });

    it('also after the flow cookie expired (state was valid, cookie is gone)', async () => {
      const browser = new Browser(h, 'compliant', false);
      const started = await browser.hit('/auth/login');
      const state = new URL(started.location as string).searchParams.get('state') as string;
      browser.jar.delete('oidc_state'); // the 10 minute cookie lapsed
      const refused = await browser.hit(`/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`);
      expect(refused.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      expectGuardPage(await browser.hit('/auth/login'), 'invalid_callback');
    });
  });

  describe('an explicit user action', () => {
    it.each(['login', 'select_account'])('prompt=%s goes through and ends the guard', async (prompt) => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone'); // arms the guard
      expect(browser.jar.has('login_guard')).toBe(true);
      expectGuardPage(await browser.hit('/auth/login'), 'invalid_callback');

      const through = await browser.hit(`/auth/login?prompt=${prompt}`);
      expect(through.status).toBe(302);
      const target = new URL(through.location as string);
      expect(target.origin).toBe(new URL(ISSUER).origin);
      expect(target.searchParams.get('prompt')).toBe(prompt);
      expect(browser.jar.has('login_guard')).toBe(false);

      // The guard is gone, not just skipped: a plain login goes through too.
      const plain = await browser.hit('/auth/login');
      expect(new URL(plain.location as string).origin).toBe(new URL(ISSUER).origin);
    });

    it('prompt=login after a refusal reaches Identity once', async () => {
      const browser = new Browser(h, 'compliant');
      await browser.visit(`${FRONTEND}/login`);
      const trace = await browser.visit(`${FRONTEND}/auth/login?prompt=login`);
      expect(trace.authorizationRedirects).toBe(1);
    });

    it.each(['consent', 'none', 'login consent', 'bogus'])('prompt=%s is not an explicit action', async (prompt) => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      const res = await browser.hit(`/auth/login?prompt=${encodeURIComponent(prompt)}`);
      expectGuardPage(res, 'invalid_callback');
    });
  });

  describe('the window', () => {
    it('blocks until the window has passed, then lets login through', async () => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');

      now = T0 + 29_999;
      expectGuardPage(await browser.hit('/auth/login'), 'invalid_callback');

      now = T0 + 30_000;
      const after = await browser.hit('/auth/login');
      expect(new URL(after.location as string).origin).toBe(new URL(ISSUER).origin);
    });

    it('does not slide: a blocked login does not extend the window', async () => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      now = T0 + 20_000;
      await browser.hit('/auth/login');
      now = T0 + 30_000;
      const after = await browser.hit('/auth/login');
      expect(new URL(after.location as string).origin).toBe(new URL(ISSUER).origin);
    });

    it('a later failure restarts the window', async () => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      now = T0 + 40_000;
      await browser.hit('/auth/callback?state=gone');
      now = T0 + 60_000;
      expectGuardPage(await browser.hit('/auth/login'), 'invalid_callback');
      now = T0 + 70_000;
      expect(new URL((await browser.hit('/auth/login')).location as string).origin).toBe(new URL(ISSUER).origin);
    });
  });

  describe('the guard cookie', () => {
    it('is signed, httpOnly, SameSite=Lax, Path=/ and lives as long as the window', async () => {
      const refused = await h.get('/auth/callback?state=gone');
      const line = cookieLine(refused, 'login_guard') as string;
      expect(line).toBeDefined();
      expect(line).toMatch(/;\s*HttpOnly/i);
      expect(line).toMatch(/;\s*SameSite=Lax/i);
      expect(line).toMatch(/;\s*Path=\//i);
      expect(line).toMatch(/;\s*Max-Age=30(;|$)/i);
      // Signed: the value is not the bare JSON.
      const value = decodeURIComponent(line.split(';')[0].slice('login_guard='.length));
      expect(value).not.toBe(serializeLoginGuard('invalid_callback', T0));
      expect(value).toContain(serializeLoginGuard('invalid_callback', T0));
      expect(value.length).toBeGreaterThan(serializeLoginGuard('invalid_callback', T0).length + 20);
    });

    it('stores only invalid_callback for an unregistered error, never the attacker string', async () => {
      const browser = new Browser(h, 'compliant', false);
      const started = await browser.hit('/auth/login');
      const state = new URL(started.location as string).searchParams.get('state') as string;
      const evil = '<script>alert(1)</script>zq7';
      const refused = await browser.hit(`/auth/callback?error=${encodeURIComponent(evil)}&state=${encodeURIComponent(state)}`);
      expect(refused.location).toBe(`${FRONTEND}/login?error=invalid_callback`);
      const line = cookieLine(refused, 'login_guard') as string;
      expect(decodeURIComponent(line)).not.toContain('zq7');
      const page = await browser.hit('/auth/login');
      expectGuardPage(page, 'invalid_callback');
      expect(page.body).not.toContain('zq7');
    });

    it('is ignored when the signature has been tampered with', async () => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      const good = browser.jar.get('login_guard') as string;
      browser.jar.set('login_guard', good.slice(0, -4) + 'AAAA');
      const res = await browser.hit('/auth/login');
      expect(new URL(res.location as string).origin).toBe(new URL(ISSUER).origin);
    });

    it('is ignored when it is a forged unsigned value', async () => {
      const browser = new Browser(h, 'compliant', false);
      browser.jar.set('login_guard', encodeURIComponent(serializeLoginGuard('access_denied', T0)));
      const res = await browser.hit('/auth/login');
      expect(new URL(res.location as string).origin).toBe(new URL(ISSUER).origin);
    });

    it('is ignored when an attacker moves the recorded time forward under a valid signature of another value', async () => {
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      const signed = decodeURIComponent(browser.jar.get('login_guard') as string);
      // Swap the JSON for a fresher one and keep the old signature.
      const swapped = signed.replace(`"ts":${T0}`, `"ts":${T0 + 3_600_000}`);
      expect(swapped).not.toBe(signed); // the mutation applied
      browser.jar.set('login_guard', encodeURIComponent(swapped));
      now = T0 + 3_600_000;
      const res = await browser.hit('/auth/login');
      expect(new URL(res.location as string).origin).toBe(new URL(ISSUER).origin);
    });
  });

  describe('a successful sign-in', () => {
    it('clears the guard', async () => {
      const claims = { fortium_user_id: 'u-1', email: 'burke@fortium.test', email_verified: true } as FortiumClaims;
      jest
        .spyOn(IdentityClient.prototype, 'exchangeCode')
        .mockResolvedValue({ idToken: 'fake.id.token', accessToken: 'fake-access', expiresIn: 3600, claims });

      const browser = new Browser(h, 'compliant', false);
      // Two attempts in flight (two tabs). Refuse the first, complete the second.
      const a = new URL(((await browser.hit('/auth/login')).location) as string).searchParams.get('state') as string;
      const b = new URL(((await browser.hit('/auth/login')).location) as string).searchParams.get('state') as string;
      await browser.hit(`/auth/callback?error=access_denied&state=${encodeURIComponent(a)}`);
      expect(browser.jar.has('login_guard')).toBe(true);
      expectGuardPage(await browser.hit('/auth/login'), 'access_denied');

      const ok = await browser.hit(`/auth/callback?code=authcode&state=${encodeURIComponent(b)}`);
      expect(ok.location).toBe(`${FRONTEND}/dashboard`);
      expect(browser.jar.has('login_guard')).toBe(false);
      expect(browser.jar.has('auth_token')).toBe(true);

      const next = await browser.hit('/auth/login');
      expect(new URL(next.location as string).origin).toBe(new URL(ISSUER).origin);
    });
  });

  it('switch-account clears the guard', async () => {
    const browser = new Browser(h, 'compliant', false);
    await browser.hit('/auth/callback?state=gone');
    expect(browser.jar.has('login_guard')).toBe(true);
    await browser.hit('/auth/switch-account');
    expect(browser.jar.has('login_guard')).toBe(false);
  });
});

describe.each(HARNESSES)('%s plugin: loginGuardSeconds', (_name, build) => {
  let now: number;

  beforeEach(() => {
    now = T0;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    global.fetch = realFetch;
  });

  it('is configurable: a 5 second window', async () => {
    const h = await build({ loginGuardSeconds: 5 });
    try {
      const refused = await h.get('/auth/callback?state=gone');
      expect(cookieLine(refused, 'login_guard')).toMatch(/;\s*Max-Age=5(;|$)/i);
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      now = T0 + 4_999;
      expectGuardPage(await browser.hit('/auth/login'), 'invalid_callback');
      now = T0 + 5_000;
      expect(new URL((await browser.hit('/auth/login')).location as string).origin).toBe(new URL(ISSUER).origin);
    } finally {
      await h.close();
    }
  });

  it('0 turns the guard off: no cookie, and login goes straight through', async () => {
    const h = await build({ loginGuardSeconds: 0 });
    try {
      const refused = await h.get('/auth/callback?state=gone');
      expect(cookieLine(refused, 'login_guard')).toBeUndefined();
      const browser = new Browser(h, 'compliant', false);
      await browser.hit('/auth/callback?state=gone');
      expect(new URL((await browser.hit('/auth/login')).location as string).origin).toBe(new URL(ISSUER).origin);
    } finally {
      await h.close();
    }
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY])('rejects %s', async (bad) => {
    await expect(build({ loginGuardSeconds: bad })).rejects.toThrow(/loginGuardSeconds/);
  });
});
