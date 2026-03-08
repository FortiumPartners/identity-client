export class EntitlementsClient {
    http;
    constructor(http) {
        this.http = http;
    }
    /**
     * List entitlements. At least one of userId, appId, or orgId is required.
     * The API returns 400 VALIDATION_ERROR if no filter is provided.
     */
    async list(params) {
        return this.http.get('/api/v1/entitlements', params);
    }
    /**
     * Auto-paginating iterator over all entitlements matching the given filters.
     * Fetches pages of `pageSize` (default 50) and yields individual Entitlement objects.
     * At least one of userId, appId, or orgId is required.
     */
    async *listAll(params) {
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
    /** Get a single entitlement by ID. Throws NotFoundError if not found. */
    async get(entitlementId) {
        const response = await this.http.get(`/api/v1/entitlements/${entitlementId}`);
        return response.entitlement;
    }
    /**
     * Grant an entitlement (binary access grant).
     * NO permissions parameter -- apps handle permissions locally.
     */
    async grant(data) {
        const response = await this.http.post('/api/v1/entitlements', data);
        return response.entitlement;
    }
    /**
     * Revoke an entitlement. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    async revoke(entitlementId) {
        await this.http.delete(`/api/v1/entitlements/${entitlementId}`);
    }
}
