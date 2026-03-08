import type { HttpClient } from '../http.js';
import type { Entitlement, ListEntitlementsParams, ListEntitlementsResponse, GrantEntitlementData } from '../types.js';
export declare class EntitlementsClient {
    private readonly http;
    constructor(http: HttpClient);
    /**
     * List entitlements. At least one of userId, appId, or orgId is required.
     * The API returns 400 VALIDATION_ERROR if no filter is provided.
     */
    list(params: ListEntitlementsParams): Promise<ListEntitlementsResponse>;
    /**
     * Auto-paginating iterator over all entitlements matching the given filters.
     * Fetches pages of `pageSize` (default 50) and yields individual Entitlement objects.
     * At least one of userId, appId, or orgId is required.
     */
    listAll(params: Omit<ListEntitlementsParams, 'limit' | 'offset'> & {
        pageSize?: number;
    }): AsyncIterable<Entitlement>;
    /** Get a single entitlement by ID. Throws NotFoundError if not found. */
    get(entitlementId: string): Promise<Entitlement>;
    /**
     * Grant an entitlement (binary access grant).
     * NO permissions parameter -- apps handle permissions locally.
     */
    grant(data: GrantEntitlementData): Promise<Entitlement>;
    /**
     * Revoke an entitlement. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    revoke(entitlementId: string): Promise<void>;
}
