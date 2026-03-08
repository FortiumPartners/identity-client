import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UsersClient } from '../../packages/admin/src/resources/users.js';
import { HttpClient } from '../../packages/admin/src/http.js';
import { NotFoundError, ValidationError } from '@fortium/identity-client/admin';
import type { User, ListUsersResponse } from '../../packages/admin/src/types.js';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeUser(overrides?: Partial<User>): User {
  return {
    userId: 'usr-001',
    email: 'test@example.com',
    emailVerified: true,
    displayName: 'Test User',
    status: 'active',
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

function mockFetch(response: { status?: number; json?: () => Promise<unknown> }) {
  const status = response.status ?? 200;
  const defaults = {
    ok: status >= 200 && status < 300,
    status,
    json: response.json ?? (() => Promise.resolve({})),
  };
  return jest.spyOn(globalThis, 'fetch').mockResolvedValue(defaults as unknown as Response);
}

describe('UsersClient', () => {
  let client: UsersClient;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch') as jest.SpiedFunction<typeof fetch>;
    const http = new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
    client = new UsersClient(http);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('list', () => {
    it('calls GET /api/v1/users with no params', async () => {
      const responseData: ListUsersResponse = {
        users: [makeUser()],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(responseData) } as unknown as Response);

      const result = await client.list();
      expect(result.users).toHaveLength(1);
      expect(result.users[0].userId).toBe('usr-001');
      expect(result.pagination.total).toBe(1);

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/users');
    });

    it('passes query params (search, status, limit, offset)', async () => {
      const responseData: ListUsersResponse = {
        users: [],
        pagination: { total: 0, limit: 10, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(responseData) } as unknown as Response);

      await client.list({ search: 'burke', status: 'active', limit: 10, offset: 20 });
      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.searchParams.get('search')).toBe('burke');
      expect(url.searchParams.get('status')).toBe('active');
      expect(url.searchParams.get('limit')).toBe('10');
      expect(url.searchParams.get('offset')).toBe('20');
    });
  });

  describe('get', () => {
    it('returns unwrapped user from GET /api/v1/users/:id', async () => {
      const user = makeUser({ userId: 'usr-123' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ user }) } as unknown as Response);

      const result = await client.get('usr-123');
      expect(result.userId).toBe('usr-123');
      expect(result.email).toBe('test@example.com');

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/users/usr-123');
    });

    it('throws NotFoundError for 404', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { code: 'USER_NOT_FOUND', message: 'User not found' } }),
      } as unknown as Response);

      await expect(client.get('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('create', () => {
    it('sends POST /api/v1/users with body and returns user', async () => {
      const user = makeUser({ userId: 'usr-new', email: 'new@example.com' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ user }) } as unknown as Response);

      const result = await client.create({ email: 'new@example.com', displayName: 'New User' });
      expect(result.userId).toBe('usr-new');

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body as string)).toEqual({ email: 'new@example.com', displayName: 'New User' });
    });

    it('throws ValidationError for 400 on bad data', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: { code: 'VALIDATION_ERROR', message: 'email is required' } }),
      } as unknown as Response);

      await expect(client.create({})).rejects.toThrow(ValidationError);
    });
  });

  describe('update', () => {
    it('sends PATCH /api/v1/users/:id with body and returns user', async () => {
      const user = makeUser({ displayName: 'Updated Name' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ user }) } as unknown as Response);

      const result = await client.update('usr-001', { displayName: 'Updated Name' });
      expect(result.displayName).toBe('Updated Name');

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('PATCH');
    });
  });

  describe('updateStatus', () => {
    it('sends PATCH /api/v1/users/:id/status', async () => {
      const user = makeUser({ status: 'suspended' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ user }) } as unknown as Response);

      const result = await client.updateStatus('usr-001', 'suspended');
      expect(result.status).toBe('suspended');

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/users/usr-001/status');
      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(JSON.parse(init.body as string)).toEqual({ status: 'suspended' });
    });
  });

  describe('delete', () => {
    it('sends DELETE /api/v1/users/:id and returns void', async () => {
      fetchSpy.mockResolvedValue({ ok: true, status: 204, json: () => Promise.reject(new Error('no json')) } as unknown as Response);

      const result = await client.delete('usr-001');
      expect(result).toBeUndefined();

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/users/usr-001');
      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('DELETE');
    });

    it('throws NotFoundError for 404 on delete', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { code: 'USER_NOT_FOUND', message: 'User not found' } }),
      } as unknown as Response);

      await expect(client.delete('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('listAll', () => {
    it('auto-paginates across multiple pages and yields all users', async () => {
      const page1: ListUsersResponse = {
        users: [makeUser({ userId: 'usr-1' }), makeUser({ userId: 'usr-2' })],
        pagination: { total: 5, limit: 2, offset: 0, hasMore: true },
      };
      const page2: ListUsersResponse = {
        users: [makeUser({ userId: 'usr-3' }), makeUser({ userId: 'usr-4' })],
        pagination: { total: 5, limit: 2, offset: 2, hasMore: true },
      };
      const page3: ListUsersResponse = {
        users: [makeUser({ userId: 'usr-5' })],
        pagination: { total: 5, limit: 2, offset: 4, hasMore: false },
      };

      fetchSpy
        .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve(page1) } as unknown as Response)
        .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve(page2) } as unknown as Response)
        .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve(page3) } as unknown as Response);

      const users: User[] = [];
      for await (const user of client.listAll({ pageSize: 2 })) {
        users.push(user);
      }

      expect(users).toHaveLength(5);
      expect(users.map(u => u.userId)).toEqual(['usr-1', 'usr-2', 'usr-3', 'usr-4', 'usr-5']);
      expect(fetchSpy).toHaveBeenCalledTimes(3);

      // Verify pagination params were sent correctly
      const url1 = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url1.searchParams.get('limit')).toBe('2');
      expect(url1.searchParams.get('offset')).toBe('0');

      const url2 = new URL(fetchSpy.mock.calls[1][0] as string);
      expect(url2.searchParams.get('offset')).toBe('2');

      const url3 = new URL(fetchSpy.mock.calls[2][0] as string);
      expect(url3.searchParams.get('offset')).toBe('4');
    });

    it('passes filter params through to each page request', async () => {
      const page1: ListUsersResponse = {
        users: [makeUser()],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(page1) } as unknown as Response);

      const users: User[] = [];
      for await (const user of client.listAll({ status: 'active', search: 'burke' })) {
        users.push(user);
      }

      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.searchParams.get('status')).toBe('active');
      expect(url.searchParams.get('search')).toBe('burke');
    });

    it('handles empty first page', async () => {
      const page1: ListUsersResponse = {
        users: [],
        pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(page1) } as unknown as Response);

      const users: User[] = [];
      for await (const user of client.listAll()) {
        users.push(user);
      }

      expect(users).toHaveLength(0);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });
  });
});
