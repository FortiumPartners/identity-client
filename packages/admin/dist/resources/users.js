export class UsersClient {
    http;
    constructor(http) {
        this.http = http;
    }
    /** List users with optional filtering and pagination */
    async list(params) {
        return this.http.get('/api/v1/users', params);
    }
    /**
     * Auto-paginating iterator over all users.
     * Fetches pages of `pageSize` (default 50) and yields individual User objects.
     */
    async *listAll(params) {
        const pageSize = params?.pageSize ?? 50;
        let offset = 0;
        let hasMore = true;
        while (hasMore) {
            const { status, search } = params ?? {};
            const response = await this.list({ limit: pageSize, offset, status, search });
            for (const user of response.users) {
                yield user;
            }
            hasMore = response.pagination.hasMore;
            offset += pageSize;
        }
    }
    /** Get a single user by ID. Throws NotFoundError if not found. */
    async get(userId) {
        const response = await this.http.get(`/api/v1/users/${userId}`);
        return response.user;
    }
    /** Create a new user. */
    async create(data) {
        const response = await this.http.post('/api/v1/users', data);
        return response.user;
    }
    /** Update user fields (email, displayName, emailVerified). */
    async update(userId, data) {
        const response = await this.http.patch(`/api/v1/users/${userId}`, data);
        return response.user;
    }
    /** Update user status (active, suspended, archived). */
    async updateStatus(userId, status) {
        const response = await this.http.patch(`/api/v1/users/${userId}/status`, { status });
        return response.user;
    }
    /** Delete a user. Throws NotFoundError if not found. */
    async delete(userId) {
        await this.http.delete(`/api/v1/users/${userId}`);
    }
}
