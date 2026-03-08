import type { HttpClient } from '../http.js';
import type {
  ApiKey,
  ListApiKeysParams,
  ListApiKeysResponse,
  ApiKeyResponse,
  ApiKeyWithKeyResponse,
  ApiKeyRevokeResponse,
  ApiKeyScopesResponse,
  CreateApiKeyData,
  UpdateApiKeyData,
} from '../types.js';

/**
 * Sub-client for managing Identity API keys.
 * API keys are used for service-to-service authentication against the Identity management API.
 * Access via `admin.apiKeys`.
 *
 * @example
 * ```typescript
 * const { apiKey, key } = await admin.apiKeys.create({ name: 'talent-key', scopes: ['users:read'] });
 * console.log('Save this key:', key); // shown only once
 * ```
 */
export class ApiKeysClient {
  constructor(private readonly http: HttpClient) {}

  /**
   * List API keys with optional filtering and pagination.
   * @param params - Filter and pagination options
   * @returns API keys array and pagination metadata
   */
  async list(params?: ListApiKeysParams): Promise<ListApiKeysResponse> {
    return this.http.get<ListApiKeysResponse>('/api/v1/api-keys', params as Record<string, unknown>);
  }

  /**
   * Get a single API key by ID.
   * @param keyId - The API key's unique identifier
   * @returns The API key metadata (does not include the plaintext key)
   * @throws {NotFoundError} If the API key does not exist
   */
  async get(keyId: string): Promise<ApiKey> {
    const response = await this.http.get<ApiKeyResponse>(`/api/v1/api-keys/${keyId}`);
    return response.apiKey;
  }

  /**
   * Create a new API key.
   * Returns the key metadata AND the plaintext key (shown only once -- store it securely).
   * @param data - Key creation data: name, optional scopes and expiration
   * @returns The API key metadata and the plaintext key
   * @throws {ValidationError} If the input data is invalid
   */
  async create(data: CreateApiKeyData): Promise<ApiKeyWithKeyResponse> {
    return this.http.post<ApiKeyWithKeyResponse>('/api/v1/api-keys', data);
  }

  /**
   * Update an API key's metadata. Uses PUT (full replacement).
   * @param keyId - The API key's unique identifier
   * @param data - Updated key metadata (name, scopes, expiresAt)
   * @returns The updated API key metadata
   * @throws {NotFoundError} If the API key does not exist
   * @throws {ValidationError} If the input data is invalid
   */
  async update(keyId: string, data: UpdateApiKeyData): Promise<ApiKey> {
    const response = await this.http.put<ApiKeyResponse>(`/api/v1/api-keys/${keyId}`, data);
    return response.apiKey;
  }

  /**
   * Revoke an API key (sets expiration to now, making it immediately unusable).
   * @param keyId - The API key's unique identifier
   * @returns The updated API key metadata and confirmation message
   * @throws {NotFoundError} If the API key does not exist
   */
  async revoke(keyId: string): Promise<ApiKeyRevokeResponse> {
    return this.http.post<ApiKeyRevokeResponse>(`/api/v1/api-keys/${keyId}/revoke`);
  }

  /**
   * Rotate an API key, generating new key material.
   * The previous key becomes invalid immediately.
   * Uses AIP-136 custom method syntax: `POST /api/v1/api-keys/:keyId:rotate`.
   * @param keyId - The API key's unique identifier
   * @returns The API key metadata and the new plaintext key
   * @throws {NotFoundError} If the API key does not exist
   */
  async rotate(keyId: string): Promise<ApiKeyWithKeyResponse> {
    return this.http.post<ApiKeyWithKeyResponse>(`/api/v1/api-keys/${keyId}:rotate`);
  }

  /**
   * Delete an API key permanently.
   * @param keyId - The API key's unique identifier
   * @throws {NotFoundError} If the API key does not exist
   */
  async delete(keyId: string): Promise<void> {
    await this.http.delete<void>(`/api/v1/api-keys/${keyId}`);
  }

  /**
   * Get the list of valid API key scopes that can be assigned to keys.
   * @returns Array of scope strings (e.g., ['users:read', 'users:write', ...])
   */
  async getScopes(): Promise<string[]> {
    const response = await this.http.get<ApiKeyScopesResponse>('/api/v1/api-keys/scopes');
    return response.scopes;
  }
}
