export class ApiKeysClient {
    http;
    constructor(http) {
        this.http = http;
    }
    /** List API keys with optional filtering and pagination. */
    async list(params) {
        return this.http.get('/api/v1/api-keys', params);
    }
    /** Get a single API key by ID. Throws NotFoundError if not found. */
    async get(keyId) {
        const response = await this.http.get(`/api/v1/api-keys/${keyId}`);
        return response.apiKey;
    }
    /**
     * Create a new API key.
     * Returns the key metadata AND the plaintext key (shown only once).
     */
    async create(data) {
        return this.http.post('/api/v1/api-keys', data);
    }
    /**
     * Update an API key. Uses PUT (not PATCH).
     */
    async update(keyId, data) {
        const response = await this.http.put(`/api/v1/api-keys/${keyId}`, data);
        return response.apiKey;
    }
    /**
     * Revoke an API key (sets expiration to now).
     * Returns the updated key metadata.
     */
    async revoke(keyId) {
        return this.http.post(`/api/v1/api-keys/${keyId}/revoke`);
    }
    /**
     * Rotate an API key (generate new key material).
     * The previous key becomes invalid immediately.
     *
     * NOTE: The API uses AIP-136 custom method syntax: POST /api/v1/api-keys/:keyId:rotate
     * (colon separator, not slash).
     */
    async rotate(keyId) {
        return this.http.post(`/api/v1/api-keys/${keyId}:rotate`);
    }
    /**
     * Delete an API key permanently. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    async delete(keyId) {
        await this.http.delete(`/api/v1/api-keys/${keyId}`);
    }
    /** Get the list of valid API key scopes. */
    async getScopes() {
        const response = await this.http.get('/api/v1/api-keys/scopes');
        return response.scopes;
    }
}
