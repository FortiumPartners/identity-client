import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { EntitlementsClient } from '../../packages/admin/src/resources/entitlements.js';
import { HttpClient } from '../../packages/admin/src/http.js';
import { NotFoundError, ValidationError } from '@fortium/identity-client/admin';
import type { Entitlement, ListEntitlementsResponse } from '../../packages/admin/src/types.js';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeEntitlement(overrides?: Partial<Entitlement>): Entitlement {
  return {
    entitlementId: 'ent-001',
    userId: 'usr-001',
    appId: 'my-app',
    orgId: null,
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('EntitlementsClient', () => {
  let client: EntitlementsClient;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch') as jest.SpiedFunction<typeof fetch>;
    const http = new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
    client = new EntitlementsClient(http);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('list', () => {
    it('calls GET /api/v1/entitlements with userId filter', async () => {
      const responseData: ListEntitlementsResponse = {
        entitlements: [makeEntitlement()],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(responseData) } as unknown as Response);

      const result = await client.list({ userId: 'usr-001' });
      expect(result.entitlements).toHaveLength(1);
      expect(result.entitlements[0].entitlementId).toBe('ent-001');

      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.pathname).toBe('/api/v1/entitlements');
      expect(url.searchParams.get('userId')).toBe('usr-001');
    });

    it('passes appId and orgId filters', async () => {
      const responseData: ListEntitlementsResponse = {
        entitlements: [],
        pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(responseData) } as unknown as Response);

      await client.list({ appId: 'gateway', orgId: 'org-001', limit: 10 });
      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.searchParams.get('appId')).toBe('gateway');
      expect(url.searchParams.get('orgId')).toBe('org-001');
      expect(url.searchParams.get('limit')).toBe('10');
    });

    it('throws ValidationError when API returns 400 for no filter', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: { code: 'VALIDATION_ERROR', message: 'At least one filter is required' } }),
      } as unknown as Response);

      await expect(client.list({})).rejects.toThrow(ValidationError);
    });
  });

  describe('get', () => {
    it('returns unwrapped entitlement from GET /api/v1/entitlements/:id', async () => {
      const entitlement = makeEntitlement({ entitlementId: 'ent-123' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ entitlement }) } as unknown as Response);

      const result = await client.get('ent-123');
      expect(result.entitlementId).toBe('ent-123');
      expect(result.appId).toBe('my-app');

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/entitlements/ent-123');
    });

    it('throws NotFoundError for 404', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { code: 'ENTITLEMENT_NOT_FOUND', message: 'Entitlement not found' } }),
      } as unknown as Response);

      await expect(client.get('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('grant', () => {
    it('sends POST /api/v1/entitlements with userId and appId only', async () => {
      const entitlement = makeEntitlement({ entitlementId: 'ent-new' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ entitlement }) } as unknown as Response);

      const result = await client.grant({ userId: 'usr-001', appId: 'my-app' });
      expect(result.entitlementId).toBe('ent-new');

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body as string);
      expect(body).toEqual({ userId: 'usr-001', appId: 'my-app' });
    });

    it('does NOT send permissions field', async () => {
      const entitlement = makeEntitlement();
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ entitlement }) } as unknown as Response);

      await client.grant({ userId: 'usr-001', appId: 'my-app' });

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body).not.toHaveProperty('permissions');
    });

    it('includes optional orgId when provided', async () => {
      const entitlement = makeEntitlement({ orgId: 'org-001' });
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ entitlement }) } as unknown as Response);

      await client.grant({ userId: 'usr-001', appId: 'my-app', orgId: 'org-001' });

      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.orgId).toBe('org-001');
    });
  });

  describe('revoke', () => {
    it('sends DELETE /api/v1/entitlements/:id and returns void', async () => {
      fetchSpy.mockResolvedValue({ ok: true, status: 204, json: () => Promise.reject(new Error('no json')) } as unknown as Response);

      const result = await client.revoke('ent-001');
      expect(result).toBeUndefined();

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain('/api/v1/entitlements/ent-001');
      const init = fetchSpy.mock.calls[0][1] as RequestInit;
      expect(init.method).toBe('DELETE');
    });

    it('throws NotFoundError for 404 on revoke', async () => {
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { code: 'ENTITLEMENT_NOT_FOUND', message: 'Entitlement not found' } }),
      } as unknown as Response);

      await expect(client.revoke('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('listAll', () => {
    it('auto-paginates across multiple pages and yields all entitlements', async () => {
      const page1: ListEntitlementsResponse = {
        entitlements: [makeEntitlement({ entitlementId: 'ent-1' }), makeEntitlement({ entitlementId: 'ent-2' })],
        pagination: { total: 3, limit: 2, offset: 0, hasMore: true },
      };
      const page2: ListEntitlementsResponse = {
        entitlements: [makeEntitlement({ entitlementId: 'ent-3' })],
        pagination: { total: 3, limit: 2, offset: 2, hasMore: false },
      };

      fetchSpy
        .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve(page1) } as unknown as Response)
        .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve(page2) } as unknown as Response);

      const entitlements: Entitlement[] = [];
      for await (const ent of client.listAll({ userId: 'usr-001', pageSize: 2 })) {
        entitlements.push(ent);
      }

      expect(entitlements).toHaveLength(3);
      expect(entitlements.map(e => e.entitlementId)).toEqual(['ent-1', 'ent-2', 'ent-3']);
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it('passes filter params through to each page request', async () => {
      const page1: ListEntitlementsResponse = {
        entitlements: [makeEntitlement()],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      fetchSpy.mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve(page1) } as unknown as Response);

      const entitlements: Entitlement[] = [];
      for await (const ent of client.listAll({ userId: 'usr-001', appId: 'gateway' })) {
        entitlements.push(ent);
      }

      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.searchParams.get('userId')).toBe('usr-001');
      expect(url.searchParams.get('appId')).toBe('gateway');
    });
  });
});
