import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MembershipsClient } from '../../packages/admin/src/resources/memberships.js';
import { HttpClient } from '../../packages/admin/src/http.js';
import { NotFoundError, ValidationError } from '@fortium/identity-client/admin';
import type { Membership, ListMembershipsResponse } from '../../packages/admin/src/types.js';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeMembership(overrides?: Partial<Membership>): Membership {
  return {
    membershipId: 'mem-001',
    userId: 'usr-001',
    orgId: 'org-001',
    role: 'member',
    status: 'active',
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('MembershipsClient', () => {
  let client: MembershipsClient;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch') as jest.SpiedFunction<typeof fetch>;
    const http = new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
    client = new MembershipsClient(http);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('list', () => {
    it('calls GET /api/v1/memberships with userId filter', async () => {
      const responseData: ListMembershipsResponse = {
        memberships: [makeMembership()],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(responseData) } as unknown as Response);

      const result = await client.list({ userId: 'usr-001' });
      expect(result.memberships).toHaveLength(1);
      expect(result.memberships[0].membershipId).toBe('mem-001');

      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.pathname).toBe('/api/v1/memberships');
      expect(url.searchParams.get('userId')).toBe('usr-001');
    });

    it('passes orgId, status, and role filters', async () => {
      const responseData: ListMembershipsResponse = {
        memberships: [],
        pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(responseData) } as unknown as Response);

      await client.list({ orgId: 'org-001', status: 'active', role: 'admin', limit: 25, offset: 10 });
      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.searchParams.get('orgId')).toBe('org-001');
      expect(url.searchParams.get('status')).toBe('active');
      expect(url.searchParams.get('role')).toBe('admin');
      expect(url.searchParams.get('limit')).toBe('25');
      expect(url.searchParams.get('offset')).toBe('10');
    });

    it('throws ValidationError when API returns 400 for no filter', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: { code: 'VALIDATION_ERROR', message: 'userId or orgId is required' } }),
      } as unknown as Response);

      await expect(client.list({})).rejects.toThrow(ValidationError);
    });
  });

  describe('get', () => {
    it('returns unwrapped membership from GET /api/v1/memberships/:id', async () => {
      const membership = makeMembership({ membershipId: 'mem-123', role: 'admin' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ membership }) } as unknown as Response);

      const result = await client.get('mem-123');
      expect(result.membershipId).toBe('mem-123');
      expect(result.role).toBe('admin');

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/memberships/mem-123');
    });

    it('throws NotFoundError for 404', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { code: 'MEMBERSHIP_NOT_FOUND', message: 'Membership not found' } }),
      } as unknown as Response);

      await expect(client.get('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('add', () => {
    it('sends POST /api/v1/memberships with body and returns membership', async () => {
      const membership = makeMembership({ membershipId: 'mem-new', role: 'admin' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ membership }) } as unknown as Response);

      const result = await client.add({ userId: 'usr-001', orgId: 'org-001', role: 'admin' });
      expect(result.membershipId).toBe('mem-new');
      expect(result.role).toBe('admin');

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body as string);
      expect(body).toEqual({ userId: 'usr-001', orgId: 'org-001', role: 'admin' });
    });

    it('includes optional status when provided', async () => {
      const membership = makeMembership({ status: 'pending' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ membership }) } as unknown as Response);

      await client.add({ userId: 'usr-001', orgId: 'org-001', role: 'member', status: 'pending' });

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.status).toBe('pending');
    });
  });

  describe('remove', () => {
    it('sends DELETE /api/v1/memberships/:id and returns void', async () => {
      fetchSpy.mockResolvedValue({ ok: true, status: 204, json: () => Promise.reject(new Error('no json')) } as unknown as Response);

      const result = await client.remove('mem-001');
      expect(result).toBeUndefined();

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/memberships/mem-001');
      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('DELETE');
    });

    it('throws NotFoundError for 404 on remove', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { code: 'MEMBERSHIP_NOT_FOUND', message: 'Membership not found' } }),
      } as unknown as Response);

      await expect(client.remove('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });
});
