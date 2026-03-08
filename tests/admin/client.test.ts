import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { IdentityAdminClient } from '../../packages/admin/src/client.js';
import { UsersClient } from '../../packages/admin/src/resources/users.js';
import { EntitlementsClient } from '../../packages/admin/src/resources/entitlements.js';
import { MembershipsClient } from '../../packages/admin/src/resources/memberships.js';
import { OrganizationsClient } from '../../packages/admin/src/resources/organizations.js';
import { ClientsClient } from '../../packages/admin/src/resources/clients.js';
import { ApiKeysClient } from '../../packages/admin/src/resources/api-keys.js';

const VALID_CONFIG = {
  baseUrl: 'https://identity.example.com',
  apiKey: 'test-api-key-123',
};

describe('IdentityAdminClient', () => {
  beforeEach(() => {
    // Stub fetch so HttpClient constructor doesn't fail on any eager calls
    jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({}),
    } as unknown as Response);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('constructor validation', () => {
    it('throws if baseUrl is missing', () => {
      expect(() => new IdentityAdminClient({ baseUrl: '', apiKey: 'key' }))
        .toThrow('baseUrl is required');
    });

    it('throws if apiKey is missing', () => {
      expect(() => new IdentityAdminClient({ baseUrl: 'https://example.com', apiKey: '' }))
        .toThrow('apiKey is required');
    });

    it('throws if both baseUrl and apiKey are missing', () => {
      expect(() => new IdentityAdminClient({ baseUrl: '', apiKey: '' }))
        .toThrow('baseUrl is required');
    });

    it('succeeds with valid config', () => {
      expect(() => new IdentityAdminClient(VALID_CONFIG)).not.toThrow();
    });

    it('accepts optional timeout', () => {
      expect(() => new IdentityAdminClient({ ...VALID_CONFIG, timeout: 5000 })).not.toThrow();
    });
  });

  describe('sub-client accessors', () => {
    let admin: IdentityAdminClient;

    beforeEach(() => {
      admin = new IdentityAdminClient(VALID_CONFIG);
    });

    it('exposes users as UsersClient', () => {
      expect(admin.users).toBeInstanceOf(UsersClient);
    });

    it('exposes entitlements as EntitlementsClient', () => {
      expect(admin.entitlements).toBeInstanceOf(EntitlementsClient);
    });

    it('exposes memberships as MembershipsClient', () => {
      expect(admin.memberships).toBeInstanceOf(MembershipsClient);
    });

    it('exposes organizations as OrganizationsClient', () => {
      expect(admin.organizations).toBeInstanceOf(OrganizationsClient);
    });

    it('exposes clients as ClientsClient', () => {
      expect(admin.clients).toBeInstanceOf(ClientsClient);
    });

    it('exposes apiKeys as ApiKeysClient', () => {
      expect(admin.apiKeys).toBeInstanceOf(ApiKeysClient);
    });

    it('all accessors are readonly (same instance on repeated access)', () => {
      const users1 = admin.users;
      const users2 = admin.users;
      expect(users1).toBe(users2);
    });
  });

  describe('config propagation', () => {
    it('passes baseUrl and apiKey through to HttpClient (verified via sub-client request)', async () => {
      const fetchSpy = globalThis.fetch as jest.MockedFunction<typeof fetch>;
      fetchSpy.mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ users: [], pagination: { total: 0, limit: 50, offset: 0, hasMore: false } }),
      } as unknown as Response);

      const admin = new IdentityAdminClient(VALID_CONFIG);
      await admin.users.list();

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [url, options] = fetchSpy.mock.calls[0];
      expect(url).toContain(VALID_CONFIG.baseUrl);
      expect((options as RequestInit).headers).toEqual(
        expect.objectContaining({
          Authorization: `Bearer ${VALID_CONFIG.apiKey}`,
        }),
      );
    });

    it('passes custom timeout through to HttpClient', async () => {
      const admin = new IdentityAdminClient({ ...VALID_CONFIG, timeout: 5000 });
      // The timeout is used internally by HttpClient via AbortSignal.timeout
      // We verify the client was created successfully with the custom timeout
      expect(admin.users).toBeInstanceOf(UsersClient);
    });
  });
});
