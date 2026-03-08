export class MembershipsClient {
    http;
    constructor(http) {
        this.http = http;
    }
    /**
     * List memberships. At least one of userId or orgId is required.
     * The API returns 400 VALIDATION_ERROR if neither is provided.
     */
    async list(params) {
        return this.http.get('/api/v1/memberships', params);
    }
    /** Get a single membership by ID. Throws NotFoundError if not found. */
    async get(membershipId) {
        const response = await this.http.get(`/api/v1/memberships/${membershipId}`);
        return response.membership;
    }
    /** Add a user to an organization with a role. */
    async add(data) {
        const response = await this.http.post('/api/v1/memberships', data);
        return response.membership;
    }
    /**
     * Remove a membership. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    async remove(membershipId) {
        await this.http.delete(`/api/v1/memberships/${membershipId}`);
    }
}
