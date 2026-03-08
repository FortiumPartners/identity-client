import { jest, describe, it, expect, afterEach } from '@jest/globals';
import { HttpClient } from '../../packages/admin/src/http.js';
import {
  IdentityApiError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  IdentityNetworkError,
} from '@fortium/identity-client/admin';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeClient(overrides?: { timeout?: number }) {
  return new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY, ...overrides });
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

describe('HttpClient', () => {
  describe('constructor validation', () => {
    it('throws if baseUrl is empty', () => {
      expect(() => new HttpClient({ baseUrl: '', apiKey: API_KEY })).toThrow('baseUrl is required');
    });

    it('throws if apiKey is empty', () => {
      expect(() => new HttpClient({ baseUrl: BASE_URL, apiKey: '' })).toThrow('apiKey is required');
    });
  });

  describe('URL building', () => {
    it('appends path to baseUrl', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ users: [] }) });
      const client = makeClient();
      await client.get('/api/v1/users');
      expect(spy).toHaveBeenCalledTimes(1);
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/users');
    });

    it('strips trailing slash from baseUrl', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = new HttpClient({ baseUrl: 'https://identity.example.com/', apiKey: API_KEY });
      await client.get('/api/v1/users');
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/users');
    });

    it('adds query params and skips undefined/null', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.get('/api/v1/users', { search: 'burke', status: undefined, limit: 10, offset: null });
      const url = spy.mock.calls[0][0] as string;
      const parsed = new URL(url);
      expect(parsed.searchParams.get('search')).toBe('burke');
      expect(parsed.searchParams.get('limit')).toBe('10');
      expect(parsed.searchParams.has('status')).toBe(false);
      expect(parsed.searchParams.has('offset')).toBe(false);
    });
  });

  describe('headers', () => {
    it('sends Authorization: Bearer header on GET', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.get('/test');
      const init = spy.mock.calls[0][1] as RequestInit;
      expect((init.headers as Record<string, string>)['Authorization']).toBe(`Bearer ${API_KEY}`);
      expect((init.headers as Record<string, string>)['Accept']).toBe('application/json');
    });

    it('sends Content-Type on POST with body', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.post('/test', { name: 'foo' });
      const init = spy.mock.calls[0][1] as RequestInit;
      expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    });

    it('does not send Content-Type on GET', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.get('/test');
      const init = spy.mock.calls[0][1] as RequestInit;
      expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined();
    });
  });

  describe('successful responses', () => {
    it('returns parsed JSON on 200', async () => {
      const payload = { user: { userId: '123', email: 'test@test.com' } };
      mockFetch({ status: 200, json: () => Promise.resolve(payload) });
      const client = makeClient();
      const result = await client.get('/api/v1/users/123');
      expect(result).toEqual(payload);
    });

    it('returns undefined on 204', async () => {
      mockFetch({ status: 204, json: () => Promise.reject(new Error('no json')) });
      const client = makeClient();
      const result = await client.delete('/api/v1/users/123');
      expect(result).toBeUndefined();
    });
  });

  describe('error status code mapping', () => {
    const errorCases = [
      [400, ValidationError, 'ValidationError'],
      [401, UnauthorizedError, 'UnauthorizedError'],
      [403, ForbiddenError, 'ForbiddenError'],
      [404, NotFoundError, 'NotFoundError'],
      [409, ConflictError, 'ConflictError'],
      [429, RateLimitError, 'RateLimitError'],
    ] as const;

    it.each(errorCases)('maps %i to %s', async (status, ErrorClass, _name) => {
      mockFetch({
        status,
        json: () => Promise.resolve({ error: { code: 'TEST_CODE', message: 'test message' } }),
      });
      const client = makeClient();
      try {
        await client.get('/test');
        fail('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ErrorClass);
        expect(err).toBeInstanceOf(IdentityApiError);
        expect((err as IdentityApiError).statusCode).toBe(status);
        expect((err as IdentityApiError).code).toBe('TEST_CODE');
        expect((err as IdentityApiError).message).toBe('test message');
      }
    });

    it('maps 5xx to base IdentityApiError', async () => {
      mockFetch({
        status: 500,
        json: () => Promise.resolve({ error: { code: 'INTERNAL_ERROR', message: 'server error' } }),
      });
      const client = makeClient();
      await expect(client.get('/test')).rejects.toThrow(IdentityApiError);
    });

    it('handles missing error body gracefully', async () => {
      mockFetch({
        status: 500,
        json: () => Promise.resolve({}),
      });
      const client = makeClient();
      try {
        await client.get('/test');
        fail('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(IdentityApiError);
        expect((err as IdentityApiError).code).toBe('UNKNOWN_ERROR');
        expect((err as IdentityApiError).message).toBe('An unknown error occurred');
      }
    });
  });

  describe('network errors', () => {
    it('wraps fetch failures in IdentityNetworkError', async () => {
      const fetchError = new TypeError('fetch failed');
      jest.spyOn(globalThis, 'fetch').mockRejectedValue(fetchError);
      const client = makeClient();
      try {
        await client.get('/test');
        fail('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(IdentityNetworkError);
        expect(err).not.toBeInstanceOf(IdentityApiError);
        expect((err as IdentityNetworkError).cause).toBe(fetchError);
      }
    });
  });

  describe('HTTP methods', () => {
    it('sends correct method for post', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.post('/test', { a: 1 });
      const init = spy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('POST');
      expect(init.body).toBe('{"a":1}');
    });

    it('sends correct method for patch', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.patch('/test', { a: 1 });
      expect((spy.mock.calls[0][1] as RequestInit).method).toBe('PATCH');
    });

    it('sends correct method for put', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.put('/test', { a: 1 });
      expect((spy.mock.calls[0][1] as RequestInit).method).toBe('PUT');
    });

    it('sends correct method for delete', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.delete('/test');
      expect((spy.mock.calls[0][1] as RequestInit).method).toBe('DELETE');
    });
  });

  describe('timeout', () => {
    it('passes AbortSignal.timeout to fetch', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient({ timeout: 5000 });
      await client.get('/test');
      const init = spy.mock.calls[0][1] as RequestInit;
      expect(init.signal).toBeDefined();
    });

    it('uses default 30000ms timeout', async () => {
      const timeoutSpy = jest.spyOn(AbortSignal, 'timeout');
      mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient();
      await client.get('/test');
      expect(timeoutSpy).toHaveBeenCalledWith(30_000);
    });

    it('uses custom timeout when provided', async () => {
      const timeoutSpy = jest.spyOn(AbortSignal, 'timeout');
      mockFetch({ status: 200, json: () => Promise.resolve({}) });
      const client = makeClient({ timeout: 5000 });
      await client.get('/test');
      expect(timeoutSpy).toHaveBeenCalledWith(5000);
    });
  });
});
