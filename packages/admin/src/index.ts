// Public API -- main client
export { IdentityAdminClient } from './client.js';

// Sub-client classes (for instanceof checks and advanced usage)
export { UsersClient } from './resources/users.js';
export { EntitlementsClient } from './resources/entitlements.js';
export { MembershipsClient } from './resources/memberships.js';
export { OrganizationsClient } from './resources/organizations.js';
export { ClientsClient } from './resources/clients.js';
export { ApiKeysClient } from './resources/api-keys.js';

// Error classes
export {
  IdentityApiError,
  NotFoundError,
  ValidationError,
  ConflictError,
  UnauthorizedError,
  ForbiddenError,
  RateLimitError,
  IdentityNetworkError,
} from './errors.js';

// Types
export type {
  AdminClientConfig,
  User,
  Entitlement,
  Membership,
  Organization,
  OidcClient,
  ApiKey,
  Pagination,
  ListUsersParams,
  CreateUserData,
  UpdateUserData,
  ListEntitlementsParams,
  GrantEntitlementData,
  ListMembershipsParams,
  AddMembershipData,
  ListOrganizationsParams,
  CreateOrganizationData,
  UpdateOrganizationData,
  ListClientsParams,
  RegisterClientData,
  UpdateClientData,
  ListApiKeysParams,
  CreateApiKeyData,
  UpdateApiKeyData,
  ListUsersResponse,
  UserResponse,
  DeleteUserResponse,
  ListEntitlementsResponse,
  EntitlementResponse,
  ListMembershipsResponse,
  MembershipResponse,
  ListOrganizationsResponse,
  OrganizationResponse,
  ListClientsResponse,
  ClientResponse,
  ClientWithSecretResponse,
  ListApiKeysResponse,
  ApiKeyResponse,
  ApiKeyWithKeyResponse,
  ApiKeyRevokeResponse,
  ApiKeyScopesResponse,
  IdentityErrorResponse,
} from './types.js';
