import type { HttpClient } from '../http.js';
import type { ApiKey, ListApiKeysParams, ListApiKeysResponse, ApiKeyWithKeyResponse, ApiKeyRevokeResponse, CreateApiKeyData, UpdateApiKeyData } from '../types.js';
export declare class ApiKeysClient {
    private readonly http;
    constructor(http: HttpClient);
    /** List API keys with optional filtering and pagination. */
    list(params?: ListApiKeysParams): Promise<ListApiKeysResponse>;
    /** Get a single API key by ID. Throws NotFoundError if not found. */
    get(keyId: string): Promise<ApiKey>;
    /**
     * Create a new API key.
     * Returns the key metadata AND the plaintext key (shown only once).
     */
    create(data: CreateApiKeyData): Promise<ApiKeyWithKeyResponse>;
    /**
     * Update an API key. Uses PUT (not PATCH).
     */
    update(keyId: string, data: UpdateApiKeyData): Promise<ApiKey>;
    /**
     * Revoke an API key (sets expiration to now).
     * Returns the updated key metadata.
     */
    revoke(keyId: string): Promise<ApiKeyRevokeResponse>;
    /**
     * Rotate an API key (generate new key material).
     * The previous key becomes invalid immediately.
     *
     * NOTE: The API uses AIP-136 custom method syntax: POST /api/v1/api-keys/:keyId:rotate
     * (colon separator, not slash).
     */
    rotate(keyId: string): Promise<ApiKeyWithKeyResponse>;
    /**
     * Delete an API key permanently. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    delete(keyId: string): Promise<void>;
    /** Get the list of valid API key scopes. */
    getScopes(): Promise<string[]>;
}
