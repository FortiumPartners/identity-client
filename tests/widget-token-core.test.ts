import { jest, describe, it, expect, beforeEach, afterAll } from '@jest/globals';
import { IdentityClient } from '../packages/core/src/identity-client.js';

/**
 * Unit tests for IdentityClient.requestWidgetToken — the RFC 8693 token
 * exchange call that powers the /auth/widget-token route in both plugins.
 *
 * Tests the HTTP wire-protocol shape and error mapping. Mocks the global
 * fetch so no real Identity calls are made.
 */

const realFetch = global.fetch;

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

const ISSUER = 'https://identity.fortiumsoftware.com';
const CLIENT_ID = 'gateway';
const CLIENT_SECRET = 'test-secret';
const USER_ID = '44a62931-8f59-416d-a482-058ee3e3ab86';

function makeClient(): IdentityClient {
  return new IdentityClient({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
}

afterAll(() => {
  global.fetch = realFetch;
});

describe('IdentityClient.requestWidgetToken', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('happy path: posts the right form-encoded body to /oidc/token and returns the raw token response', async () => {
    mockFetchResolved({
      body: {
        access_token: 'fake.jwt.value',
        token_type: 'Bearer',
        expires_in: 300,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        scope: 'ideas:widget',
      },
    });
    const client = makeClient();
    const result = await client.requestWidgetToken(USER_ID, 'ideas-api');

    expect(result.access_token).toBe('fake.jwt.value');
    expect(result.token_type).toBe('Bearer');
    expect(result.expires_in).toBe(300);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = (global.fetch as jest.Mock<typeof fetch>).mock.calls[0];
    expect(url.toString()).toBe(`${ISSUER}/oidc/token`);
    expect((init as RequestInit).method).toBe('POST');
    const body = new URLSearchParams((init as RequestInit).body as string);
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(body.get('subject_token')).toBe(USER_ID);
    expect(body.get('subject_token_type')).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(body.get('audience')).toBe('ideas-api');
    expect(body.get('client_id')).toBe(CLIENT_ID);
    expect(body.get('client_secret')).toBe(CLIENT_SECRET);
  });

  it('Identity 400 invalid_target → throws Error with statusCode=400 and oauthError=invalid_target', async () => {
    mockFetchResolved({
      status: 400,
      body: {
        error: 'invalid_target',
        error_description: "audience 'random-api' is not in this client's allowed_exchange_audiences",
      },
    });
    const client = makeClient();
    await expect(client.requestWidgetToken(USER_ID, 'random-api')).rejects.toMatchObject({
      statusCode: 400,
      oauthError: 'invalid_target',
      message: expect.stringContaining('allowed_exchange_audiences'),
    });
  });

  it('Identity 400 invalid_grant → throws with statusCode=400 and oauthError=invalid_grant', async () => {
    mockFetchResolved({
      status: 400,
      body: {
        error: 'invalid_grant',
        error_description: 'subject_token does not resolve to a known user',
      },
    });
    const client = makeClient();
    await expect(client.requestWidgetToken('unknown-uuid', 'ideas-api')).rejects.toMatchObject({
      statusCode: 400,
      oauthError: 'invalid_grant',
    });
  });

  it('Identity 500 → throws with statusCode=500 (no oauthError-required body parsing)', async () => {
    mockFetchResolved({ status: 500, body: 'internal error' });
    const client = makeClient();
    await expect(client.requestWidgetToken(USER_ID, 'ideas-api')).rejects.toMatchObject({
      statusCode: 500,
    });
  });

  it('non-JSON error body → defaults to invalid_request, status preserved', async () => {
    global.fetch = jest.fn<typeof fetch>().mockResolvedValue({
      ok: false,
      status: 502,
      json: async () => {
        throw new Error('not json');
      },
      text: async () => '<html>Bad Gateway</html>',
    } as unknown as Response);
    const client = makeClient();
    await expect(client.requestWidgetToken(USER_ID, 'ideas-api')).rejects.toMatchObject({
      statusCode: 502,
      oauthError: 'invalid_request',
    });
  });

  it('network failure (timeout) → throws without statusCode (caller maps to 503)', async () => {
    mockFetchRejected(
      Object.assign(new Error('signal timed out'), { name: 'TimeoutError' }),
    );
    const client = makeClient();
    await expect(client.requestWidgetToken(USER_ID, 'ideas-api')).rejects.toThrow();
    const fetchMock = global.fetch as jest.Mock<typeof fetch>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
