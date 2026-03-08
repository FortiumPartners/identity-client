import { jest, describe, it, expect, afterEach } from '@jest/globals';
import { ClientsClient } from '../../packages/admin/src/resources/clients.js';
import { HttpClient } from '../../packages/admin/src/http.js';
import { NotFoundError, ConflictError } from '@fortium/identity-client/admin';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeClient() {
  const http = new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
  return new ClientsClient(http);
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

const sampleClient = {
  clientId: 'my-app',
  clientName: 'My Application',
  redirectUris: ['https://myapp.com/callback'],
  postLogoutRedirectUris: ['https://myapp.com'],
  scopes: ['openid', 'profile', 'email'],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  require2fa: false,
  allowSelfRegistration: true,
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
};

describe('ClientsClient', () => {
  describe('list', () => {
    it('returns clients with pagination', async () => {
      const body = {
        clients: [sampleClient],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      mockFetch({ status: 200, json: () => Promise.resolve(body) });
      const client = makeClient();
      const result = await client.list();
      expect(result.clients).toHaveLength(1);
      expect(result.clients[0].clientId).toBe('my-app');
    });

    it('passes query parameters', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ clients: [], pagination: { total: 0, limit: 50, offset: 0, hasMore: false } }),
      });
      const client = makeClient();
      await client.list({ search: 'app', limit: 10 });
      const url = spy.mock.calls[0][0] as string;
      expect(url).toContain('search=app');
      expect(url).toContain('limit=10');
    });
  });

  describe('get', () => {
    it('returns a single client', async () => {
      mockFetch({ status: 200, json: () => Promise.resolve({ client: sampleClient }) });
      const client = makeClient();
      const result = await client.get('my-app');
      expect(result.clientId).toBe('my-app');
      expect(result.clientName).toBe('My Application');
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ client: sampleClient }) });
      const client = makeClient();
      await client.get('my-app');
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/clients/my-app');
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'CLIENT_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.get('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('register', () => {
    it('returns client with secret', async () => {
      const responseBody = { client: sampleClient, clientSecret: 'secret-abc-123' };
      mockFetch({ status: 200, json: () => Promise.resolve(responseBody) });
      const client = makeClient();
      const result = await client.register({
        clientId: 'my-app',
        clientName: 'My Application',
        redirectUris: ['https://myapp.com/callback'],
      });
      expect(result.client.clientId).toBe('my-app');
      expect(result.clientSecret).toBe('secret-abc-123');
    });

    it('sends POST to /api/v1/clients', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ client: sampleClient, clientSecret: 'secret' }),
      });
      const client = makeClient();
      await client.register({
        clientId: 'new-app',
        clientName: 'New App',
        redirectUris: ['https://new.com/cb'],
      });
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/clients');
      expect(options.method).toBe('POST');
    });

    it('throws ConflictError for duplicate client', async () => {
      mockFetch({
        status: 409,
        json: () => Promise.resolve({ error: { code: 'CLIENT_EXISTS', message: 'Client already exists' } }),
      });
      const client = makeClient();
      await expect(
        client.register({ clientId: 'my-app', clientName: 'Dup', redirectUris: [] }),
      ).rejects.toThrow(ConflictError);
    });
  });

  describe('update', () => {
    it('uses PUT method (not PATCH)', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ client: sampleClient }) });
      const client = makeClient();
      await client.update('my-app', { clientName: 'Updated Name' });
      const [, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(options.method).toBe('PUT');
    });

    it('returns updated client', async () => {
      const updated = { ...sampleClient, clientName: 'Updated' };
      mockFetch({ status: 200, json: () => Promise.resolve({ client: updated }) });
      const client = makeClient();
      const result = await client.update('my-app', { clientName: 'Updated' });
      expect(result.clientName).toBe('Updated');
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ client: sampleClient }) });
      const client = makeClient();
      await client.update('my-app', { clientName: 'X' });
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/clients/my-app');
    });
  });

  describe('delete', () => {
    it('sends DELETE request', async () => {
      const spy = mockFetch({ status: 204 });
      const client = makeClient();
      await client.delete('my-app');
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/clients/my-app');
      expect(options.method).toBe('DELETE');
    });

    it('returns void on success', async () => {
      mockFetch({ status: 204 });
      const client = makeClient();
      const result = await client.delete('my-app');
      expect(result).toBeUndefined();
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'CLIENT_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.delete('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('rotateSecret', () => {
    it('returns client with new secret', async () => {
      const responseBody = { client: sampleClient, clientSecret: 'new-secret-xyz' };
      mockFetch({ status: 200, json: () => Promise.resolve(responseBody) });
      const client = makeClient();
      const result = await client.rotateSecret('my-app');
      expect(result.client.clientId).toBe('my-app');
      expect(result.clientSecret).toBe('new-secret-xyz');
    });

    it('sends POST to rotate-secret endpoint', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ client: sampleClient, clientSecret: 'new' }),
      });
      const client = makeClient();
      await client.rotateSecret('my-app');
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/clients/my-app/rotate-secret');
      expect(options.method).toBe('POST');
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'CLIENT_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.rotateSecret('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });
});
