# @fortium/identity-client/admin

Typed TypeScript client for Fortium Identity's REST management API (`/api/v1/*`). Provides programmatic access to users, entitlements, memberships, organizations, OIDC clients, and API keys.

Zero runtime dependencies. ESM and CJS compatible.

## Installation

The admin client is a subpath export of the main package -- no separate install needed:

```json
{
  "@fortium/identity-client": "github:FortiumPartners/identity-client"
}
```

Pin to a specific commit to avoid CDN caching issues:

```json
{
  "@fortium/identity-client": "https://github.com/FortiumPartners/identity-client/tarball/<commit-sha>"
}
```

## Quick Start

```typescript
import { IdentityAdminClient } from '@fortium/identity-client/admin';

const admin = new IdentityAdminClient({
  baseUrl: 'https://identity.fortiumsoftware.com',
  apiKey: process.env.IDENTITY_API_KEY!,
});

// List users
const { users, pagination } = await admin.users.list({ search: 'burke' });

// Grant app access
await admin.entitlements.grant({
  userId: 'usr_abc123',
  appId: 'my-app',
});
```

## Sub-Clients

The `IdentityAdminClient` exposes six resource sub-clients:

### users

Manage Identity user accounts.

```typescript
// List with pagination and filtering
const { users, pagination } = await admin.users.list({
  status: 'active',
  search: 'john',
  limit: 25,
  offset: 0,
});

// Auto-paginate through all users
for await (const user of admin.users.listAll({ status: 'active' })) {
  console.log(user.email);
}

// Get a single user
const user = await admin.users.get('usr_abc123');

// Create a user
const newUser = await admin.users.create({
  email: 'jane@example.com',
  displayName: 'Jane Doe',
});

// Update user fields
const updated = await admin.users.update('usr_abc123', {
  displayName: 'Jane Smith',
});

// Update user status
const suspended = await admin.users.updateStatus('usr_abc123', 'suspended');

// Delete a user
await admin.users.delete('usr_abc123');
```

### entitlements

Manage binary app access grants. Entitlements control whether a user can access a given app -- nothing more. Fine-grained permissions (roles, features) are managed by each app locally.

```typescript
// List entitlements (at least one filter required)
const { entitlements, pagination } = await admin.entitlements.list({
  userId: 'usr_abc123',
});

// Auto-paginate through all entitlements for an app
for await (const ent of admin.entitlements.listAll({ appId: 'talent' })) {
  console.log(`${ent.userEmail} has access`);
}

// Get a single entitlement
const ent = await admin.entitlements.get('ent_xyz789');

// Grant access (no permissions field -- apps handle that locally)
const granted = await admin.entitlements.grant({
  userId: 'usr_abc123',
  appId: 'talent',
  orgId: 'org_456', // optional
});

// Revoke access
await admin.entitlements.revoke('ent_xyz789');
```

### memberships

Manage organization memberships.

```typescript
// List memberships (at least one of userId or orgId required)
const { memberships, pagination } = await admin.memberships.list({
  orgId: 'org_456',
  role: 'admin',
});

// Get a single membership
const membership = await admin.memberships.get('mem_abc123');

// Add a user to an organization
const added = await admin.memberships.add({
  userId: 'usr_abc123',
  orgId: 'org_456',
  role: 'member',
});

// Remove a membership
await admin.memberships.remove('mem_abc123');
```

### organizations

Manage organizations.

```typescript
// List with filtering
const { organizations, pagination } = await admin.organizations.list({
  orgType: 'client',
  status: 'active',
  search: 'Acme',
});

// Auto-paginate through all organizations
for await (const org of admin.organizations.listAll({ orgType: 'client' })) {
  console.log(org.name);
}

// Get a single organization
const org = await admin.organizations.get('org_456');

// Create an organization
const newOrg = await admin.organizations.create({
  name: 'Acme Corp',
  orgType: 'client',
});

// Update an organization
const updated = await admin.organizations.update('org_456', {
  name: 'Acme Corporation',
});
```

### clients

Manage OIDC client registrations (platform operations).

```typescript
// List clients
const { clients, pagination } = await admin.clients.list({ search: 'talent' });

// Get a single client
const client = await admin.clients.get('talent');

// Register a new client (returns secret -- shown only once)
const { client: newClient, clientSecret } = await admin.clients.register({
  clientId: 'my-new-app',
  clientName: 'My New App',
  redirectUris: ['https://app.example.com/auth/callback'],
});
console.log('Save this secret:', clientSecret);

// Update a client (PUT -- full update)
const updated = await admin.clients.update('my-new-app', {
  clientName: 'My Renamed App',
  redirectUris: ['https://app.example.com/auth/callback'],
});

// Rotate client secret (previous secret invalidated immediately)
const { clientSecret: newSecret } = await admin.clients.rotateSecret('my-new-app');

// Delete a client
await admin.clients.delete('my-new-app');
```

### apiKeys

Manage Identity API keys for service-to-service authentication.

```typescript
// List API keys
const { apiKeys, pagination } = await admin.apiKeys.list({
  search: 'talent',
  includeExpired: false,
});

// Get a single key
const key = await admin.apiKeys.get('key_abc123');

// Create a key (returns plaintext key -- shown only once)
const { apiKey, key: plaintextKey } = await admin.apiKeys.create({
  name: 'talent-service-key',
  scopes: ['users:read', 'entitlements:write'],
  expiresAt: '2027-01-01T00:00:00Z',
});
console.log('Save this key:', plaintextKey);

// Update key metadata
const updated = await admin.apiKeys.update('key_abc123', {
  name: 'talent-service-key-v2',
  scopes: ['users:read', 'users:write', 'entitlements:write'],
});

// Revoke a key (sets expiration to now)
const { apiKey: revoked } = await admin.apiKeys.revoke('key_abc123');

// Rotate a key (generate new key material, old key invalidated)
const { key: newKey } = await admin.apiKeys.rotate('key_abc123');

// Delete a key permanently
await admin.apiKeys.delete('key_abc123');

// Get available scopes
const scopes = await admin.apiKeys.getScopes();
```

## Authorization Model

This client operates within a **hybrid authorization model** where Identity and apps each own distinct parts of the access control story:

### What Identity handles (coarse-grained)

- **Users** -- identity, email, display name, account status
- **Entitlements** -- binary app access grants ("can this user access Talent?")
- **Organizations** -- org identity, type, membership
- **OIDC Clients** -- platform-level client registration

### What apps handle (fine-grained)

- **Roles** -- admin, editor, viewer, etc.
- **Permissions** -- what actions a user can perform within the app
- **Feature flags** -- app-specific feature access
- **User preferences** -- app-local settings

### How it works in practice

1. A user logs in to your app via Identity (OIDC)
2. Identity checks the user has an **entitlement** for your app (binary yes/no)
3. Your app checks its **own database** for the user's role and permissions
4. Admin operations use a **service API key** to call the Identity API

```
User clicks "Manage Users"
    |
    v
App checks: does this user have admin role? (app's own DB)
    |
    v  (yes)
App calls: admin.users.list()  (Identity API, authenticated with API key)
    |
    v
Identity returns user data
    |
    v
App renders admin UI
```

The API key authenticates the **app** to Identity. The app is responsible for checking that the **logged-in user** has permission to perform admin operations before making these calls.

## Error Handling

All errors are typed and can be caught with `instanceof`:

```typescript
import {
  IdentityApiError,
  NotFoundError,
  ValidationError,
  ConflictError,
  UnauthorizedError,
  ForbiddenError,
  RateLimitError,
  IdentityNetworkError,
} from '@fortium/identity-client/admin';

try {
  const user = await admin.users.get('nonexistent');
} catch (err) {
  if (err instanceof NotFoundError) {
    // 404 -- resource not found
    console.log(err.code);    // e.g., 'USER_NOT_FOUND'
    console.log(err.message); // e.g., 'User not found'
  } else if (err instanceof ValidationError) {
    // 400 -- invalid input
  } else if (err instanceof ConflictError) {
    // 409 -- duplicate resource
  } else if (err instanceof UnauthorizedError) {
    // 401 -- invalid or missing API key
  } else if (err instanceof ForbiddenError) {
    // 403 -- insufficient permissions
  } else if (err instanceof RateLimitError) {
    // 429 -- too many requests
  } else if (err instanceof IdentityApiError) {
    // Any other API error (5xx, etc.)
    console.log(err.statusCode);
  } else if (err instanceof IdentityNetworkError) {
    // Network failure (DNS, timeout, connection refused)
    console.log(err.cause); // Original error
  }
}
```

### Error Hierarchy

```
Error
  +-- IdentityApiError (statusCode, code, message)
  |     +-- NotFoundError        (404)
  |     +-- ValidationError      (400)
  |     +-- ConflictError        (409)
  |     +-- UnauthorizedError    (401)
  |     +-- ForbiddenError       (403)
  |     +-- RateLimitError       (429)
  +-- IdentityNetworkError (message, cause)
```

## TypeScript Types

All types are exported from the subpath:

```typescript
import type {
  // Configuration
  AdminClientConfig,

  // Resource types
  User,
  Entitlement,
  Membership,
  Organization,
  OidcClient,
  ApiKey,
  Pagination,

  // Request parameter types
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

  // Response types
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
} from '@fortium/identity-client/admin';
```

## Configuration

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `baseUrl` | `string` | Yes | -- | Identity base URL (e.g., `https://identity.fortiumsoftware.com`) |
| `apiKey` | `string` | Yes | -- | API key for `Authorization: Bearer` header |
| `timeout` | `number` | No | `30000` | Request timeout in milliseconds |
