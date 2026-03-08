import { jest, describe, it, expect, afterEach } from '@jest/globals';
import { OrganizationsClient } from '../../packages/admin/src/resources/organizations.js';
import { HttpClient } from '../../packages/admin/src/http.js';
import { NotFoundError, ValidationError } from '@fortium/identity-client/admin';

const BASE_URL = 'https://identity.example.com';
const API_KEY = 'test-api-key-123';

function makeClient() {
  const http = new HttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
  return new OrganizationsClient(http);
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

const sampleOrg = {
  orgId: 'org-1',
  name: 'Fortium Partners',
  orgType: 'fortium_internal' as const,
  status: 'active' as const,
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
};

describe('OrganizationsClient', () => {
  describe('list', () => {
    it('returns paginated organizations', async () => {
      const body = {
        organizations: [sampleOrg],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false },
      };
      mockFetch({ status: 200, json: () => Promise.resolve(body) });
      const client = makeClient();
      const result = await client.list();
      expect(result.organizations).toHaveLength(1);
      expect(result.organizations[0].orgId).toBe('org-1');
      expect(result.pagination.total).toBe(1);
    });

    it('passes query parameters', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({ organizations: [], pagination: { total: 0, limit: 50, offset: 0, hasMore: false } }),
      });
      const client = makeClient();
      await client.list({ status: 'active', orgType: 'client', search: 'test', limit: 10, offset: 5 });
      const url = spy.mock.calls[0][0] as string;
      expect(url).toContain('status=active');
      expect(url).toContain('orgType=client');
      expect(url).toContain('search=test');
      expect(url).toContain('limit=10');
      expect(url).toContain('offset=5');
    });
  });

  describe('get', () => {
    it('returns a single organization', async () => {
      mockFetch({ status: 200, json: () => Promise.resolve({ organization: sampleOrg }) });
      const client = makeClient();
      const org = await client.get('org-1');
      expect(org.orgId).toBe('org-1');
      expect(org.name).toBe('Fortium Partners');
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ organization: sampleOrg }) });
      const client = makeClient();
      await client.get('org-1');
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/organizations/org-1');
    });

    it('throws NotFoundError for 404', async () => {
      mockFetch({
        status: 404,
        json: () => Promise.resolve({ error: { code: 'ORGANIZATION_NOT_FOUND', message: 'Not found' } }),
      });
      const client = makeClient();
      await expect(client.get('nonexistent')).rejects.toThrow(NotFoundError);
    });
  });

  describe('create', () => {
    it('creates an organization', async () => {
      mockFetch({ status: 200, json: () => Promise.resolve({ organization: sampleOrg }) });
      const client = makeClient();
      const org = await client.create({ name: 'Fortium Partners', orgType: 'fortium_internal' });
      expect(org.name).toBe('Fortium Partners');
    });

    it('sends POST with correct body', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ organization: sampleOrg }) });
      const client = makeClient();
      await client.create({ name: 'Test Org', orgType: 'client' });
      const [url, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://identity.example.com/api/v1/organizations');
      expect(options.method).toBe('POST');
      expect(JSON.parse(options.body as string)).toEqual({ name: 'Test Org', orgType: 'client' });
    });

    it('throws ValidationError for 400', async () => {
      mockFetch({
        status: 400,
        json: () => Promise.resolve({ error: { code: 'VALIDATION_ERROR', message: 'Name is required' } }),
      });
      const client = makeClient();
      await expect(client.create({ name: '', orgType: 'client' })).rejects.toThrow(ValidationError);
    });
  });

  describe('update', () => {
    it('updates an organization via PATCH', async () => {
      const updated = { ...sampleOrg, name: 'Updated Name' };
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ organization: updated }) });
      const client = makeClient();
      const org = await client.update('org-1', { name: 'Updated Name' });
      expect(org.name).toBe('Updated Name');
      const [, options] = spy.mock.calls[0] as [string, RequestInit];
      expect(options.method).toBe('PATCH');
    });

    it('calls correct URL', async () => {
      const spy = mockFetch({ status: 200, json: () => Promise.resolve({ organization: sampleOrg }) });
      const client = makeClient();
      await client.update('org-1', { status: 'suspended' });
      const url = spy.mock.calls[0][0] as string;
      expect(url).toBe('https://identity.example.com/api/v1/organizations/org-1');
    });
  });

  describe('listAll', () => {
    it('auto-paginates across multiple pages', async () => {
      const org1 = { ...sampleOrg, orgId: 'org-1' };
      const org2 = { ...sampleOrg, orgId: 'org-2' };
      const org3 = { ...sampleOrg, orgId: 'org-3' };

      const spy = jest.spyOn(globalThis, 'fetch');
      spy
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            organizations: [org1, org2],
            pagination: { total: 3, limit: 2, offset: 0, hasMore: true },
          }),
        } as unknown as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            organizations: [org3],
            pagination: { total: 3, limit: 2, offset: 2, hasMore: false },
          }),
        } as unknown as Response);

      const client = makeClient();
      const results: Array<{ orgId: string }> = [];
      for await (const org of client.listAll({ pageSize: 2 })) {
        results.push(org);
      }

      expect(results).toHaveLength(3);
      expect(results.map(o => o.orgId)).toEqual(['org-1', 'org-2', 'org-3']);
      expect(spy).toHaveBeenCalledTimes(2);
    });

    it('yields nothing for empty results', async () => {
      mockFetch({
        status: 200,
        json: () => Promise.resolve({
          organizations: [],
          pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
        }),
      });

      const client = makeClient();
      const results: unknown[] = [];
      for await (const org of client.listAll()) {
        results.push(org);
      }
      expect(results).toHaveLength(0);
    });

    it('passes filter params through pages', async () => {
      const spy = mockFetch({
        status: 200,
        json: () => Promise.resolve({
          organizations: [],
          pagination: { total: 0, limit: 50, offset: 0, hasMore: false },
        }),
      });

      const client = makeClient();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _ of client.listAll({ status: 'active', orgType: 'client', search: 'test' })) {
        // drain
      }

      const url = spy.mock.calls[0][0] as string;
      expect(url).toContain('status=active');
      expect(url).toContain('orgType=client');
      expect(url).toContain('search=test');
    });
  });
});
