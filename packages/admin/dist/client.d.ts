import type { AdminClientConfig } from './types.js';
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
export declare class IdentityAdminClient {
    readonly users: UsersClient;
    readonly entitlements: EntitlementsClient;
    readonly memberships: MembershipsClient;
    readonly organizations: OrganizationsClient;
    readonly clients: ClientsClient;
    readonly apiKeys: ApiKeysClient;
    constructor(config: AdminClientConfig);
}
