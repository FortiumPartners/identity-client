import { jest, describe, it, expect, afterEach } from '@jest/globals';
import { ApiKeysClient } from '../../packages/admin/src/resources/api-keys.js';
import { HttpClient } from '../../packages/admin/src/http.js';
import { NotFoundError, ValidationError } from '@fortium/identity-client/admin';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeClient() {
  const http = new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
  return new ApiKeysClient(http);
}

function mockFetch(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  const defaults = {
    ok: response.status ? response.status >= 200 && response.status < 300 : true,
    status: response.status ?? 200,
    json: response.json ?? (() => Promise.resolve({})),
  };
  return jest.spyOn(globalThis, 'fetch').mockResolvedValue(defaults as unknown as Response);
}

afterEach(() => {
  jest.restoreAllMocks();
});

const sampleKey = {
  keyId: 'key-1',
  name: 'Production Key',
  keyPrefix: 'idk_prod_',
  scopes: ['users:read', 'users:write'],
  lastUsedAt: '2026-03-01T00:00:00Z',
  expiresAt: '2027-03-01T00:00:00Z',
  createdAt: '2026-01-01T00:00:00Z',
};

describe('ApiKeysClient', () => {
  describe('list', () => {
    it('returns api keys with pagination', async () => {
      const body = {
        apiKeys: [sampleKey],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      mockFetch({ status: 200, json: () => Promise.resolve(body) });
      const client = makeClient();
      const result = await client.list();
      expect(result.apiKeys).toHaveLength(1);
      expect(result.apiKeys[0].keyId).toBe('key-1');
    });

    it('passes query parameters', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ apiKeys: [], pagination: { total: 0, limit: 50, offset: 0, hasMore: false } }),
      });
      const client = makeClient();
      await client.list({ search: 'prod', includeExpired: true, limit: 10 });
      const url = spy.mock.calls[0][0] as string;
      expect(url).toContain('search=prod');
      expect(url).toContain('includeExpired=true');
      expect(url).toContain('limit=10');
    });
  });

  describe('get', () => {
    it('returns a single api key', async () => {
      mockFetch({ status: 200, json: () => Promise.resolve({ apiKey: sampleKey }) });
      const client = makeClient();
      const key = await client.get('key-1');
      expect(key.keyId).toBe('key-1');
      expect(key.name).toBe('Production Key');
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ apiKey: sampleKey }) });
      const client = makeClient();
      await client.get('key-1');
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/api-keys/key-1');
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'API_KEY_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.get('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('create', () => {
    it('returns key with plaintext secret', async () => {
      const responseBody = { apiKey: sampleKey, key: 'idk_prod_abc123xyz', message: 'Key created' };
      mockFetch({ status: 200, json: () => Promise.resolve(responseBody) });
      const client = makeClient();
      const result = await client.create({ name: 'Production Key', scopes: ['users:read'] });
      expect(result.apiKey.keyId).toBe('key-1');
      expect(result.key).toBe('idk_prod_abc123xyz');
      expect(result.message).toBe('Key created');
    });

    it('sends POST to /api/v1/api-keys', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ apiKey: sampleKey, key: 'k', message: 'ok' }),
      });
      const client = makeClient();
      await client.create({ name: 'Test', scopes: ['users:read'] });
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/api-keys');
      expect(options.method).toBe('POST');
    });

    it('throws ValidationError for 400', async () => {
      mockFetch({
        status: 400,
        json: () => Promise.resolve({ error: { code: 'VALIDATION_ERROR', message: 'Name is required' } }),
      });
      const client = makeClient();
      await expect(client.create({ name: '' })).rejects.toThrow(ValidationError);
    });
  });

  describe('update', () => {
    it('uses PUT method (not PATCH)', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ apiKey: sampleKey }) });
      const client = makeClient();
      await client.update('key-1', { name: 'Updated Key' });
      const [, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(options.method).toBe('PUT');
    });

    it('returns updated key', async () => {
      const updated = { ...sampleKey, name: 'Updated' };
      mockFetch({ status: 200, json: () => Promise.resolve({ apiKey: updated }) });
      const client = makeClient();
      const key = await client.update('key-1', { name: 'Updated' });
      expect(key.name).toBe('Updated');
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ apiKey: sampleKey }) });
      const client = makeClient();
      await client.update('key-1', { name: 'X' });
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/api-keys/key-1');
    });
  });

  describe('revoke', () => {
    it('returns revoked key with message', async () => {
      const revokedKey = { ...sampleKey, expiresAt: '2026-03-08T00:00:00Z' };
      const responseBody = { apiKey: revokedKey, message: 'Key revoked' };
      mockFetch({ status: 200, json: () => Promise.resolve(responseBody) });
      const client = makeClient();
      const result = await client.revoke('key-1');
      expect(result.apiKey.keyId).toBe('key-1');
      expect(result.message).toBe('Key revoked');
    });

    it('sends POST to revoke endpoint', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ apiKey: sampleKey, message: 'Revoked' }),
      });
      const client = makeClient();
      await client.revoke('key-1');
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/api-keys/key-1/revoke');
      expect(options.method).toBe('POST');
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'API_KEY_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.revoke('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('rotate', () => {
    it('uses colon-syntax URL (POST to /api/v1/api-keys/{id}:rotate)', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ apiKey: sampleKey, key: 'new-key', message: 'Rotated' }),
      });
      const client = makeClient();
      await client.rotate('key-1');
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/api-keys/key-1:rotate');
      expect(options.method).toBe('POST');
    });

    it('returns new key material', async () => {
      const responseBody = { apiKey: sampleKey, key: 'idk_prod_newkey456', message: 'Key rotated' };
      mockFetch({ status: 200, json: () => Promise.resolve(responseBody) });
      const client = makeClient();
      const result = await client.rotate('key-1');
      expect(result.key).toBe('idk_prod_newkey456');
      expect(result.apiKey.keyId).toBe('key-1');
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'API_KEY_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.rotate('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('delete', () => {
    it('sends DELETE request', async () => {
      const spy = mockFetch({ status: 204 });
      const client = makeClient();
      await client.delete('key-1');
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/api-keys/key-1');
      expect(options.method).toBe('DELETE');
    });

    it('returns void on success', async () => {
      mockFetch({ status: 204 });
      const client = makeClient();
      const result = await client.delete('key-1');
      expect(result).toBeUndefined();
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'API_KEY_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.delete('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('getScopes', () => {
    it('returns string array of scopes', async () => {
      const scopes = ['users:read', 'users:write', 'entitlements:read', 'entitlements:write'];
      mockFetch({ status: 200, json: () => Promise.resolve({ scopes }) });
      const client = makeClient();
      const result = await client.getScopes();
      expect(result).toEqual(scopes);
      expect(Array.isArray(result)).toBe(true);
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ scopes: [] }) });
      const client = makeClient();
      await client.getScopes();
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/api-keys/scopes');
    });

    it('returns empty array when no scopes', async () => {
      mockFetch({ status: 200, json: () => Promise.resolve({ scopes: [] }) });
      const client = makeClient();
      const result = await client.getScopes();
      expect(result).toEqual([]);
    });
  });
});
