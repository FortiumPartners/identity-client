export class OrganizationsClient {
    http;
    constructor(http) {
        this.http = http;
    }
    /** List organizations with optional filtering and pagination. */
    async list(params) {
        return this.http.get('/api/v1/organizations', params);
    }
    /**
     * Auto-paginating iterator over all organizations.
     * Fetches pages of `pageSize` (default 50) and yields individual Organization objects.
     */
    async *listAll(params) {
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
    /** Get a single organization by ID. Throws NotFoundError if not found. */
    async get(orgId) {
        const response = await this.http.get(`/api/v1/organizations/${orgId}`);
        return response.organization;
    }
    /** Create a new organization. */
    async create(data) {
        const response = await this.http.post('/api/v1/organizations', data);
        return response.organization;
    }
    /** Update an organization. */
    async update(orgId, data) {
        const response = await this.http.patch(`/api/v1/organizations/${orgId}`, data);
        return response.organization;
    }
}
