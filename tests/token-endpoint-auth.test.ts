import { jest, describe, it, expect, afterEach } from '@jest/globals';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import express from 'express';
import cookieParser from 'cookie-parser';
import { createHmac } from 'node:crypto';

/**
 * Token endpoint client authentication (identity#180).
 *
 * The SDK authenticates with client_secret_basic by default (RFC 6749 section
 * 2.3.1: the server MUST support Basic, credentials in the body are NOT
 * RECOMMENDED) and with client_secret_post when `tokenEndpointAuthMethod` says
 * so. The Basic header is built from the RFC text here, independently of the
 * SDK, and also decoded the way oidc-provider's lib/shared/token_auth.js does.
 *
 * Secrets are assembled at runtime from fragments; none is a real credential.
 */

import { IdentityClient, type IdentityClientConfig } from '../packages/core/src/identity-client.js';
import { createSessionToken } from '../packages/core/src/session.js';
import { serializeAccessToken } from '../packages/core/src/access-token-cookie.js';
import { identityPlugin } from '../packages/fastify/src/plugin.js';
import { createIdentityRouter } from '../packages/express/src/plugin.js';
import type { FortiumClaims, OIDCState } from '../packages/core/src/types.js';

const ISSUER = 'https://identity.example.com';
const ACCESS_TOKEN = 'o2m5Vq8xLr3TnK1bWcYd7EhJf0AsGpZuQiXe4MvNt9k';
const USER_ID = '44a62931-8f59-416d-a482-058ee3e3ab86';

// ':', '+', '/', '%', space and '=' are each a character the encoding must treat specially.
const SPECIAL_SECRET = ['fake', ':', 'a+b', '/', 'c%d', ' ', 'e=f', '&', '~', "'()*!"].join('');
const SPECIAL_ID = ['app', ' ', 'one:two', '%', '+'].join('');
const NON_ASCII_SECRET = ['fake', 'é', '中', '\u{1F511}'].join('');
const PLAIN_ID = 'gateway';
const PLAIN_SECRET = 'fake-plain-secret';

const realFetch = global.fetch;

afterEach(() => {
  global.fetch = realFetch;
  jest.restoreAllMocks();
});

/**
 * application/x-www-form-urlencoded per RFC 6749 Appendix B / the WHATWG
 * serializer, written out byte by byte: ALPHA DIGIT and * - . _ pass through,
 * space is '+', every other UTF-8 byte is %XX with upper-case hex.
 */
function rfcFormEncode(value: string): string {
  let out = '';
  for (const byte of Buffer.from(value, 'utf8')) {
    const ch = String.fromCharCode(byte);
    if (/[A-Za-z0-9*\-._]/.test(ch)) out += ch;
    else if (byte === 0x20) out += '+';
    else out += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

function rfcBasicHeader(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${rfcFormEncode(clientId)}:${rfcFormEncode(clientSecret)}`, 'utf8').toString('base64')}`;
}

// oidc-provider 8.8.1 lib/shared/token_auth.js decodeAuthToken + findClientId, copied for the round trip.
const noVSCHAR = /[^\x20-\x7E]/;
function decodeAuthToken(token: string): string {
  const authToken = decodeURIComponent(token.replace(/\+/g, '%20'));
  if (noVSCHAR.test(authToken)) {
    throw new Error('invalid character found');
  }
  return authToken;
}
function oidcProviderDecode(authorization: string): { clientId: string; clientSecret: string } {
  const parts = authorization.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'basic') throw new Error('invalid authorization header value format');
  const basic = Buffer.from(parts[1], 'base64').toString('utf8');
  const i = basic.indexOf(':');
  if (i === -1) throw new Error('invalid authorization header value format');
  return { clientId: decodeAuthToken(basic.slice(0, i)), clientSecret: decodeAuthToken(basic.slice(i + 1)) };
}

function mockTokenEndpoint() {
  const fetchMock = jest.fn<typeof fetch>(async () => {
    const body = { access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 300, id_token: 'fake.id.token' };
    return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) } as unknown as Response;
  });
  global.fetch = fetchMock;
  return fetchMock;
}

function lastRequest(fetchMock: jest.Mock<typeof fetch>) {
  const [url, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
  const reqInit = init as RequestInit;
  return {
    url: String(url),
    headers: reqInit.headers as Record<string, string>,
    body: new URLSearchParams(reqInit.body as string),
    rawBody: reqInit.body as string,
  };
}

const OIDC_STATE: OIDCState = {
  state: 's',
  nonce: 'n',
  codeVerifier: 'v',
  redirectUri: 'https://app.test/auth/callback',
  ts: 0,
};

// Each call site that talks to /oidc/token, driven through the public method.
const CALL_SITES: Array<[string, (c: IdentityClient) => Promise<unknown>]> = [
  [
    'exchangeCode',
    (c) => {
      jest.spyOn(c, 'validateIdToken').mockResolvedValue({ fortium_user_id: USER_ID } as FortiumClaims);
      return c.exchangeCode('fake-code', OIDC_STATE);
    },
  ],
  ['refreshToken', (c) => c.refreshToken('fake-refresh-token')],
  ['requestWidgetToken', (c) => c.requestWidgetToken(ACCESS_TOKEN, 'ideas-api')],
];

function makeClient(overrides: Partial<IdentityClientConfig> = {}): IdentityClient {
  return new IdentityClient({ issuer: ISSUER, clientId: PLAIN_ID, clientSecret: PLAIN_SECRET, ...overrides });
}

describe.each(CALL_SITES)('%s authenticates with client_secret_basic by default', (_name, call) => {
  it('sends the RFC 6749 section 2.3.1 Basic header and no credentials in the body', async () => {
    const fetchMock = mockTokenEndpoint();
    await call(makeClient());

    const req = lastRequest(fetchMock);
    expect(req.url).toBe(`${ISSUER}/oidc/token`);
    expect(req.headers.Authorization).toBe(rfcBasicHeader(PLAIN_ID, PLAIN_SECRET));
    expect(req.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(req.body.has('client_secret')).toBe(false);
    expect(req.body.has('client_id')).toBe(false);
    expect(req.body.get('grant_type')).toBeTruthy();
    expect(req.rawBody).not.toContain(PLAIN_SECRET);
  });

  it('form-encodes client_id and client_secret before joining and base64 encoding', async () => {
    const fetchMock = mockTokenEndpoint();
    await call(makeClient({ clientId: SPECIAL_ID, clientSecret: SPECIAL_SECRET }));

    const header = lastRequest(fetchMock).headers.Authorization;
    expect(header).toBe(rfcBasicHeader(SPECIAL_ID, SPECIAL_SECRET));
    // The decoded credentials carry the separators, so a naive join would be ambiguous.
    const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');
    expect(decoded).toBe(`${rfcFormEncode(SPECIAL_ID)}:${rfcFormEncode(SPECIAL_SECRET)}`);
    expect(decoded.split(':')).toHaveLength(2);
    // Only the first ':' separates the two, so the encoded ':' in the id and secret is %3A.
    expect(decoded).toContain('%3A');
    expect(decoded).toContain('%2B');
    expect(decoded).toContain('%2F');
    expect(decoded).toContain('%25');
  });

  it('round-trips through the decoding oidc-provider applies to the Authorization header', async () => {
    const fetchMock = mockTokenEndpoint();
    await call(makeClient({ clientId: SPECIAL_ID, clientSecret: SPECIAL_SECRET }));

    expect(oidcProviderDecode(lastRequest(fetchMock).headers.Authorization)).toEqual({
      clientId: SPECIAL_ID,
      clientSecret: SPECIAL_SECRET,
    });
  });

  it('encodes a non-ASCII secret as UTF-8 percent bytes', async () => {
    const fetchMock = mockTokenEndpoint();
    await call(makeClient({ clientSecret: NON_ASCII_SECRET }));

    const header = lastRequest(fetchMock).headers.Authorization;
    expect(header).toBe(rfcBasicHeader(PLAIN_ID, NON_ASCII_SECRET));
    const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');
    expect(decoded).toBe(`${PLAIN_ID}:fake%C3%A9%E4%B8%AD%F0%9F%94%91`);
    expect(/[^\x20-\x7E]/.test(decoded)).toBe(false);
  });
});

describe.each(CALL_SITES)('%s with tokenEndpointAuthMethod client_secret_post', (_name, call) => {
  it('keeps client_id and client_secret in the body and sends no Authorization header', async () => {
    const fetchMock = mockTokenEndpoint();
    await call(makeClient({ clientId: SPECIAL_ID, clientSecret: SPECIAL_SECRET, tokenEndpointAuthMethod: 'client_secret_post' }));

    const req = lastRequest(fetchMock);
    expect(req.body.get('client_id')).toBe(SPECIAL_ID);
    expect(req.body.get('client_secret')).toBe(SPECIAL_SECRET);
    expect(req.headers.Authorization).toBeUndefined();
    expect(req.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
  });
});

describe('tokenEndpointAuthMethod', () => {
  it('an explicit client_secret_basic behaves like the default', async () => {
    const fetchMock = mockTokenEndpoint();
    await makeClient({ tokenEndpointAuthMethod: 'client_secret_basic' }).refreshToken('fake-refresh-token');
    expect(lastRequest(fetchMock).headers.Authorization).toBe(rfcBasicHeader(PLAIN_ID, PLAIN_SECRET));
  });

  it('an unknown value is refused instead of silently falling back', () => {
    expect(
      () => makeClient({ tokenEndpointAuthMethod: 'client_secret_posts' as unknown as 'client_secret_post' }),
    ).toThrow(TypeError);
  });
});

describe('plugins pass tokenEndpointAuthMethod to the client', () => {
  const COOKIE_SECRET = 'plugin-test-cookie-secret-not-real';
  const JWT_SECRET = 'plugin-test-jwt-secret-not-real';
  const pluginOpts = {
    issuer: ISSUER,
    clientId: PLAIN_ID,
    clientSecret: PLAIN_SECRET,
    callbackUrl: 'https://app.test/auth/callback',
    frontendUrl: 'https://app.test',
    jwtSecret: JWT_SECRET,
    sessionIssuer: 'gateway',
  };

  async function sessionToken(): Promise<string> {
    return createSessionToken(
      { fortiumUserId: USER_ID, email: 'burke@fortium.test' },
      { jwtSecret: JWT_SECRET, issuer: 'gateway', expiresIn: '1h' },
    );
  }

  async function fastifyWidgetRequest(extra: { tokenEndpointAuthMethod?: 'client_secret_post' }) {
    const app = fastify({ logger: false });
    await app.register(fastifyCookie, { secret: COOKIE_SECRET });
    await app.register(
      async (instance) => {
        await instance.register(identityPlugin, { ...pluginOpts, ...extra });
      },
      { prefix: '/auth' },
    );
    const res = await app.inject({
      method: 'GET',
      url: '/auth/widget-token?audience=ideas-api',
      cookies: {
        auth_token: app.signCookie(await sessionToken()),
        identity_access_token: app.signCookie(serializeAccessToken(ACCESS_TOKEN, 3600, USER_ID)),
      },
    });
    await app.close();
    return res.statusCode;
  }

  function expressSign(value: string): string {
    return `s:${value}.${createHmac('sha256', COOKIE_SECRET).update(value).digest('base64').replace(/=+$/, '')}`;
  }

  async function expressWidgetRequest(extra: { tokenEndpointAuthMethod?: 'client_secret_post' }) {
    const app = express();
    app.use(cookieParser(COOKIE_SECRET));
    app.use('/auth', createIdentityRouter({ ...pluginOpts, ...extra }));
    const server: Server = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const { port } = server.address() as AddressInfo;
    const cookie = [
      `auth_token=${encodeURIComponent(expressSign(await sessionToken()))}`,
      `identity_access_token=${encodeURIComponent(expressSign(serializeAccessToken(ACCESS_TOKEN, 3600, USER_ID)))}`,
    ].join('; ');
    const res = await realFetch(`http://127.0.0.1:${port}/auth/widget-token?audience=ideas-api`, {
      headers: { cookie },
    });
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return res.status;
  }

  const PLUGINS: Array<[string, typeof fastifyWidgetRequest]> = [
    ['Fastify', fastifyWidgetRequest],
    ['Express', expressWidgetRequest],
  ];

  describe.each(PLUGINS)('%s', (_name, run) => {
    it('defaults to Basic', async () => {
      const fetchMock = mockTokenEndpoint();
      expect(await run({})).toBe(200);
      const req = lastRequest(fetchMock);
      expect(req.headers.Authorization).toBe(rfcBasicHeader(PLAIN_ID, PLAIN_SECRET));
      expect(req.body.has('client_secret')).toBe(false);
    });

    it('client_secret_post puts the credentials in the body', async () => {
      const fetchMock = mockTokenEndpoint();
      expect(await run({ tokenEndpointAuthMethod: 'client_secret_post' })).toBe(200);
      const req = lastRequest(fetchMock);
      expect(req.headers.Authorization).toBeUndefined();
      expect(req.body.get('client_id')).toBe(PLAIN_ID);
      expect(req.body.get('client_secret')).toBe(PLAIN_SECRET);
    });
  });
});
