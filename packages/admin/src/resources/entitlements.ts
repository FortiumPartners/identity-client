import type { HttpClient } from '../http.js';
import type {
  Entitlement,
  ListEntitlementsParams,
  ListEntitlementsResponse,
  EntitlementResponse,
  GrantEntitlementData,
} from '../types.js';

/**
 * Sub-client for managing binary app access grants (entitlements).
 * Entitlements answer "can this user access this app?" -- nothing more.
 * Fine-grained permissions are managed by each app locally.
 * Access via `admin.entitlements`.
 *
 * @example
 * ```typescript
 * await admin.entitlements.grant({ userId: 'usr_abc', appId: 'talent' });
 * ```
 */
export class EntitlementsClient {
  constructor(private readonly http: HttpClient) {}

  /**
   * List entitlements with required filtering and optional pagination.
   * At least one of userId, appId, or orgId must be provided.
   * @param params - Filter and pagination options (at least one filter required)
   * @returns Entitlements array and pagination metadata
   * @throws {ValidationError} If no filter (userId, appId, or orgId) is provided
   */
  async list(params: ListEntitlementsParams): Promise<ListEntitlementsResponse> {
    return this.http.get<ListEntitlementsResponse>('/api/v1/entitlements', params as Record<string, unknown>);
  }

  /**
   * Auto-paginating async generator that yields all entitlements matching the given filters.
   * Fetches pages of `pageSize` (default 50) and yields individual Entitlement objects.
   * @param params - Filter options (at least one of userId, appId, orgId required) and optional pageSize
   * @yields {Entitlement} Individual entitlement objects
   */
  async *listAll(
    params: Omit<ListEntitlementsParams, 'limit' | 'offset'> & { pageSize?: number },
  ): AsyncIterable<Entitlement> {
    const pageSize = params?.pageSize ?? 50;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const { userId, appId, orgId } = params ?? {};
      const response = await this.list({ limit: pageSize, offset, userId, appId, orgId });
      for (const entitlement of response.entitlements) {
        yield entitlement;
      }
      hasMore = response.pagination.hasMore;
      offset += pageSize;
    }
  }

  /**
   * Get a single entitlement by ID.
   * @param entitlementId - The entitlement's unique identifier
   * @returns The entitlement object
   * @throws {NotFoundError} If the entitlement does not exist
   */
  async get(entitlementId: string): Promise<Entitlement> {
    const response = await this.http.get<EntitlementResponse>(`/api/v1/entitlements/${entitlementId}`);
    return response.entitlement;
  }

  /**
   * Grant an entitlement (binary access grant).
   * No permissions parameter -- apps handle permissions locally.
   * @param data - Grant data: userId, appId, and optional orgId
   * @returns The created entitlement object
   * @throws {ConflictError} If the entitlement already exists
   * @throws {ValidationError} If the input data is invalid
   */
  async grant(data: GrantEntitlementData): Promise<Entitlement> {
    const response = await this.http.post<EntitlementResponse>('/api/v1/entitlements', data);
    return response.entitlement;
  }

  /**
   * Revoke an entitlement, removing the user's access to the app.
   * @param entitlementId - The entitlement's unique identifier
   * @throws {NotFoundError} If the entitlement does not exist
   */
  async revoke(entitlementId: string): Promise<void> {
    await this.http.delete<void>(`/api/v1/entitlements/${entitlementId}`);
  }
}
