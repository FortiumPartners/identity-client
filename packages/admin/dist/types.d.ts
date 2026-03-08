/** Configuration for IdentityAdminClient */
export interface AdminClientConfig {
    /** Identity base URL (e.g., 'https://identity.fortiumsoftware.com') */
    baseUrl: string;
    /** API key for Authorization: Bearer header */
    apiKey: string;
    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;
}
/**
 * User resource.
 * Source: /api/v1/users formatUser() in src/routes/api/v1/users.js
 */
export interface User {
    userId: string;
    email: string;
    emailVerified: boolean;
    displayName: string | null;
    status: 'active' | 'suspended' | 'archived';
    createdAt: string;
    updatedAt: string;
}
/**
 * Entitlement resource -- a binary access grant.
 * NO permissions field. Apps handle permissions locally.
 * Source: /api/v1/entitlements formatEntitlement()
 */
export interface Entitlement {
    entitlementId: string;
    userId: string;
    appId: string;
    orgId: string | null;
    createdAt: string;
    updatedAt: string;
    userEmail?: string;
    userDisplayName?: string;
    orgName?: string;
}
/**
 * Membership resource.
 * Source: /api/v1/memberships formatMembership()
 */
export interface Membership {
    membershipId: string;
    userId: string;
    orgId: string;
    role: 'admin' | 'member' | 'readonly';
    status: 'active' | 'pending' | 'revoked';
    createdAt: string;
    updatedAt: string;
    orgName?: string;
    orgType?: string;
    userEmail?: string;
    userDisplayName?: string;
}
/**
 * Organization resource.
 * Source: /api/v1/organizations formatOrganization()
 */
export interface Organization {
    orgId: string;
    name: string;
    orgType: 'fortium_internal' | 'client' | 'partner' | 'candidate_pool';
    status: 'active' | 'suspended' | 'archived';
    createdAt: string;
    updatedAt: string;
}
/**
 * OIDC Client resource. Platform operations only.
 * Source: /api/v1/clients formatClient()
 */
export interface OidcClient {
    clientId: string;
    clientName: string;
    redirectUris: string[];
    postLogoutRedirectUris: string[];
    scopes: string[];
    grantTypes: string[];
    responseTypes: string[];
    tokenEndpointAuthMethod: string;
    require2fa: boolean;
    allowSelfRegistration: boolean;
    createdAt: string;
    updatedAt: string;
}
/**
 * API Key resource. Identity management keys only.
 * Source: api-key-service.js formatKey()
 */
export interface ApiKey {
    keyId: string;
    name: string;
    keyPrefix: string;
    scopes: string[];
    lastUsedAt: string | null;
    expiresAt: string | null;
    createdAt: string;
}
/** Standard pagination metadata returned by paginated endpoints */
export interface Pagination {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
}
/** Parameters for users.list() */
export interface ListUsersParams {
    limit?: number;
    offset?: number;
    status?: 'active' | 'suspended' | 'archived';
    search?: string;
}
/** Parameters for users.create() */
export interface CreateUserData {
    email?: string;
    displayName?: string;
    emailVerified?: boolean;
    status?: 'active' | 'suspended' | 'archived';
}
/** Parameters for users.update() */
export interface UpdateUserData {
    email?: string;
    displayName?: string;
    emailVerified?: boolean;
}
/** Parameters for entitlements.list() -- at least one filter required */
export interface ListEntitlementsParams {
    userId?: string;
    appId?: string;
    orgId?: string;
    limit?: number;
    offset?: number;
}
/** Parameters for entitlements.grant() -- NO permissions field */
export interface GrantEntitlementData {
    userId: string;
    appId: string;
    orgId?: string;
}
/** Parameters for memberships.list() -- at least one of userId or orgId required */
export interface ListMembershipsParams {
    userId?: string;
    orgId?: string;
    status?: 'active' | 'pending' | 'revoked';
    role?: 'admin' | 'member' | 'readonly';
    limit?: number;
    offset?: number;
}
/** Parameters for memberships.add() */
export interface AddMembershipData {
    userId: string;
    orgId: string;
    role: 'admin' | 'member' | 'readonly';
    status?: 'active' | 'pending' | 'revoked';
}
/** Parameters for organizations.list() */
export interface ListOrganizationsParams {
    limit?: number;
    offset?: number;
    status?: 'active' | 'suspended' | 'archived';
    orgType?: 'fortium_internal' | 'client' | 'partner' | 'candidate_pool';
    search?: string;
}
/** Parameters for organizations.create() */
export interface CreateOrganizationData {
    name: string;
    orgType: 'fortium_internal' | 'client' | 'partner' | 'candidate_pool';
    status?: 'active' | 'suspended' | 'archived';
}
/** Parameters for organizations.update() */
export interface UpdateOrganizationData {
    name?: string;
    orgType?: 'fortium_internal' | 'client' | 'partner' | 'candidate_pool';
    status?: 'active' | 'suspended' | 'archived';
}
/** Parameters for clients.list() */
export interface ListClientsParams {
    limit?: number;
    offset?: number;
    search?: string;
}
/** Parameters for clients.register() */
export interface RegisterClientData {
    clientId: string;
    clientName: string;
    redirectUris: string[];
    postLogoutRedirectUris?: string[];
    scopes?: string[];
    grantTypes?: string[];
    responseTypes?: string[];
    tokenEndpointAuthMethod?: string;
    require2fa?: boolean;
    allowSelfRegistration?: boolean;
}
/** Parameters for clients.update() -- uses PUT (full update) */
export interface UpdateClientData {
    clientName?: string;
    redirectUris?: string[];
    postLogoutRedirectUris?: string[];
    scopes?: string[];
    grantTypes?: string[];
    responseTypes?: string[];
    tokenEndpointAuthMethod?: string;
    require2fa?: boolean;
    allowSelfRegistration?: boolean;
}
/** Parameters for apiKeys.list() */
export interface ListApiKeysParams {
    limit?: number;
    offset?: number;
    search?: string;
    includeExpired?: boolean;
}
/** Parameters for apiKeys.create() */
export interface CreateApiKeyData {
    name: string;
    scopes?: string[];
    expiresAt?: string;
}
/** Parameters for apiKeys.update() -- uses PUT */
export interface UpdateApiKeyData {
    name?: string;
    scopes?: string[];
    expiresAt?: string;
}
/** Response from users.list() */
export interface ListUsersResponse {
    users: User[];
    pagination: Pagination;
}
/** Response from users.get(), users.create(), users.update(), users.updateStatus() */
export interface UserResponse {
    user: User;
}
/** Response from users.delete() */
export interface DeleteUserResponse {
    success: boolean;
    message: string;
}
/** Response from entitlements.list() */
export interface ListEntitlementsResponse {
    entitlements: Entitlement[];
    pagination: Pagination;
}
/** Response from entitlements.get() */
export interface EntitlementResponse {
    entitlement: Entitlement;
}
/** Response from memberships.list() */
export interface ListMembershipsResponse {
    memberships: Membership[];
    pagination: Pagination;
}
/** Response from memberships.get() */
export interface MembershipResponse {
    membership: Membership;
}
/** Response from organizations.list() */
export interface ListOrganizationsResponse {
    organizations: Organization[];
    pagination: Pagination;
}
/** Response from organizations.get(), organizations.create(), organizations.update() */
export interface OrganizationResponse {
    organization: Organization;
}
/** Response from clients.list() */
export interface ListClientsResponse {
    clients: OidcClient[];
    pagination: Pagination;
}
/** Response from clients.get(), clients.update() */
export interface ClientResponse {
    client: OidcClient;
}
/** Response from clients.register(), clients.rotateSecret() */
export interface ClientWithSecretResponse {
    client: OidcClient;
    clientSecret: string;
}
/** Response from apiKeys.list() */
export interface ListApiKeysResponse {
    apiKeys: ApiKey[];
    pagination: Pagination;
}
/** Response from apiKeys.get() */
export interface ApiKeyResponse {
    apiKey: ApiKey;
}
/** Response from apiKeys.create(), apiKeys.rotate() */
export interface ApiKeyWithKeyResponse {
    apiKey: ApiKey;
    key: string;
    message: string;
}
/** Response from apiKeys.revoke() */
export interface ApiKeyRevokeResponse {
    apiKey: ApiKey;
    message: string;
}
/** Response from apiKeys.getScopes() */
export interface ApiKeyScopesResponse {
    scopes: string[];
}
/** Shape of error responses from the Identity API */
export interface IdentityErrorResponse {
    error: {
        code: string;
        message: string;
    };
}
