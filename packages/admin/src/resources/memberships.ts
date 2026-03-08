import type { HttpClient } from '../http.js';
import type {
  Membership,
  ListMembershipsParams,
  ListMembershipsResponse,
  MembershipResponse,
  AddMembershipData,
} from '../types.js';

/**
 * Sub-client for managing organization memberships.
 * Access via `admin.memberships`.
 *
 * @example
 * ```typescript
 * const { memberships } = await admin.memberships.list({ orgId: 'org_456' });
 * ```
 */
export class MembershipsClient {
  constructor(private readonly http: HttpClient) {}

  /**
   * List memberships with required filtering and optional pagination.
   * At least one of userId or orgId must be provided.
   * @param params - Filter and pagination options
   * @returns Memberships array and pagination metadata
   * @throws {ValidationError} If neither userId nor orgId is provided
   */
  async list(params: ListMembershipsParams): Promise<ListMembershipsResponse> {
    return this.http.get<ListMembershipsResponse>('/api/v1/memberships', params as Record<string, unknown>);
  }

  /**
   * Get a single membership by ID.
   * @param membershipId - The membership's unique identifier
   * @returns The membership object
   * @throws {NotFoundError} If the membership does not exist
   */
  async get(membershipId: string): Promise<Membership> {
    const response = await this.http.get<MembershipResponse>(`/api/v1/memberships/${membershipId}`);
    return response.membership;
  }

  /**
   * Add a user to an organization with a role.
   * @param data - Membership data: userId, orgId, role, and optional status
   * @returns The created membership object
   * @throws {ConflictError} If the membership already exists
   * @throws {ValidationError} If the input data is invalid
   */
  async add(data: AddMembershipData): Promise<Membership> {
    const response = await this.http.post<MembershipResponse>('/api/v1/memberships', data);
    return response.membership;
  }

  /**
   * Remove a membership, detaching the user from the organization.
   * @param membershipId - The membership's unique identifier
   * @throws {NotFoundError} If the membership does not exist
   */
  async remove(membershipId: string): Promise<void> {
    await this.http.delete<void>(`/api/v1/memberships/${membershipId}`);
  }
}
