import type { HttpClient } from '../http.js';
import type { Organization, ListOrganizationsParams, ListOrganizationsResponse, CreateOrganizationData, UpdateOrganizationData } from '../types.js';
export declare class OrganizationsClient {
    private readonly http;
    constructor(http: HttpClient);
    /** List organizations with optional filtering and pagination. */
    list(params?: ListOrganizationsParams): Promise<ListOrganizationsResponse>;
    /**
     * Auto-paginating iterator over all organizations.
     * Fetches pages of `pageSize` (default 50) and yields individual Organization objects.
     */
    listAll(params?: Omit<ListOrganizationsParams, 'limit' | 'offset'> & {
        pageSize?: number;
    }): AsyncIterable<Organization>;
    /** Get a single organization by ID. Throws NotFoundError if not found. */
    get(orgId: string): Promise<Organization>;
    /** Create a new organization. */
    create(data: CreateOrganizationData): Promise<Organization>;
    /** Update an organization. */
    update(orgId: string, data: UpdateOrganizationData): Promise<Organization>;
}
