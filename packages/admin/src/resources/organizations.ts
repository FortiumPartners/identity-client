import type { HttpClient } from '../http.js';
import type {
  Organization,
  ListOrganizationsParams,
  ListOrganizationsResponse,
  OrganizationResponse,
  CreateOrganizationData,
  UpdateOrganizationData,
} from '../types.js';

/**
 * Sub-client for managing organizations.
 * Access via `admin.organizations`.
 *
 * @example
 * ```typescript
 * const { organizations } = await admin.organizations.list({ orgType: 'client' });
 * ```
 */
export class OrganizationsClient {
  constructor(private readonly http: HttpClient) {}

  /**
   * List organizations with optional filtering and pagination.
   * @param params - Filter and pagination options
   * @returns Organizations array and pagination metadata
   */
  async list(params?: ListOrganizationsParams): Promise<ListOrganizationsResponse> {
    return this.http.get<ListOrganizationsResponse>('/api/v1/organizations', params as Record<string, unknown>);
  }

  /**
   * Auto-paginating async generator that yields all organizations matching the given filters.
   * Fetches pages of `pageSize` (default 50) and yields individual Organization objects.
   * @param params - Filter options and optional pageSize
   * @yields {Organization} Individual organization objects
   */
  async *listAll(
    params?: Omit<ListOrganizationsParams, 'limit' | 'offset'> & { pageSize?: number },
  ): AsyncIterable<Organization> {
    const pageSize = params?.pageSize ?? 50;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const { status, orgType, search } = params ?? {};
      const response = await this.list({ limit: pageSize, offset, status, orgType, search });
      for (const org of response.organizations) {
        yield org;
      }
      hasMore = response.pagination.hasMore;
      offset += pageSize;
    }
  }

  /**
   * Get a single organization by ID.
   * @param orgId - The organization's unique identifier
   * @returns The organization object
   * @throws {NotFoundError} If the organization does not exist
   */
  async get(orgId: string): Promise<Organization> {
    const response = await this.http.get<OrganizationResponse>(`/api/v1/organizations/${orgId}`);
    return response.organization;
  }

  /**
   * Create a new organization.
   * @param data - Organization creation data: name, orgType, and optional status
   * @returns The created organization object
   * @throws {ConflictError} If an organization with the same name already exists
   * @throws {ValidationError} If the input data is invalid
   */
  async create(data: CreateOrganizationData): Promise<Organization> {
    const response = await this.http.post<OrganizationResponse>('/api/v1/organizations', data);
    return response.organization;
  }

  /**
   * Update an organization.
   * @param orgId - The organization's unique identifier
   * @param data - Fields to update (only provided fields are changed)
   * @returns The updated organization object
   * @throws {NotFoundError} If the organization does not exist
   */
  async update(orgId: string, data: UpdateOrganizationData): Promise<Organization> {
    const response = await this.http.patch<OrganizationResponse>(`/api/v1/organizations/${orgId}`, data);
    return response.organization;
  }
}
