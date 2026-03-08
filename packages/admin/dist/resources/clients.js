export class ClientsClient {
    http;
    constructor(http) {
        this.http = http;
    }
    /** List OIDC clients with optional filtering and pagination. */
    async list(params) {
        return this.http.get('/api/v1/clients', params);
    }
    /** Get a single OIDC client by client_id. Throws NotFoundError if not found. */
    async get(clientId) {
        const response = await this.http.get(`/api/v1/clients/${clientId}`);
        return response.client;
    }
    /**
     * Register a new OIDC client.
     * Returns the client AND the plaintext client secret (shown only once).
     */
    async register(data) {
        return this.http.post('/api/v1/clients', data);
    }
    /**
     * Update an OIDC client. Uses PUT (not PATCH).
     * Note: clientId cannot be changed.
     */
    async update(clientId, data) {
        const response = await this.http.put(`/api/v1/clients/${clientId}`, data);
        return response.client;
    }
    /**
     * Delete an OIDC client. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    async delete(clientId) {
        await this.http.delete(`/api/v1/clients/${clientId}`);
    }
    /**
     * Rotate the client secret. Returns the client AND the new plaintext secret.
     * The previous secret becomes invalid immediately.
     */
    async rotateSecret(clientId) {
        return this.http.post(`/api/v1/clients/${clientId}/rotate-secret`);
    }
}
