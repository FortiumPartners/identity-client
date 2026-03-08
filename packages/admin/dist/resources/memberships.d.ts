import type { HttpClient } from '../http.js';
import type { Membership, ListMembershipsParams, ListMembershipsResponse, AddMembershipData } from '../types.js';
export declare class MembershipsClient {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * List memberships. At least one of userId or orgId is required.
     * The API returns 400 VALIDATION_ERROR if neither is provided.
     */
    list(params: ListMembershipsParams): Promise<ListMembershipsResponse>;
    /** Get a single membership by ID. Throws NotFoundError if not found. */
    get(membershipId: string): Promise<Membership>;
    /** Add a user to an organization with a role. */
    add(data: AddMembershipData): Promise<Membership>;
    /**
     * Remove a membership. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    remove(membershipId: string): Promise<void>;
}
