import { HttpClient } from './http.js';
import { UsersClient } from './resources/users.js';
import { EntitlementsClient } from './resources/entitlements.js';
import { MembershipsClient } from './resources/memberships.js';
import { OrganizationsClient } from './resources/organizations.js';
import { ClientsClient } from './resources/clients.js';
import { ApiKeysClient } from './resources/api-keys.js';
/**
 * IdentityAdminClient -- main entry point for the Identity Admin API.
 *
 * Provides typed access to all Identity management resources through
 * sub-client accessors (users, entitlements, memberships, organizations,
 * clients, apiKeys).
 *
 * @example
 * ```typescript
 * const admin = new IdentityAdminClient({
 *   baseUrl: 'https://identity.fortiumsoftware.com',
 *   apiKey: 'your-api-key',
 * });
 *
 * const { users, pagination } = await admin.users.list({ search: 'burke' });
 * ```
 */
export class IdentityAdminClient {
    users;
    entitlements;
    memberships;
    organizations;
    clients;
    apiKeys;
    constructor(config) {
        if (!config.baseUrl)
            throw new Error('baseUrl is required');
        if (!config.apiKey)
            throw new Error('apiKey is required');
        const http = new HttpClient(config);
        this.users = new UsersClient(http);
        this.entitlements = new EntitlementsClient(http);
        this.memberships = new MembershipsClient(http);
        this.organizations = new OrganizationsClient(http);
        this.clients = new ClientsClient(http);
        this.apiKeys = new ApiKeysClient(http);
    }
}
