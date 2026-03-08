import type { HttpClient } from '../http.js';
import type {
  OidcClient,
  ListClientsParams,
  ListClientsResponse,
  ClientResponse,
  ClientWithSecretResponse,
  RegisterClientData,
  UpdateClientData,
} from '../types.js';

/**
 * Sub-client for managing OIDC client registrations.
 * Platform operations only -- used for registering and configuring Fortium apps.
 * Access via `admin.clients`.
 *
 * @example
 * ```typescript
 * const { client, clientSecret } = await admin.clients.register({
 *   clientId: 'my-app',
 *   clientName: 'My App',
 *   redirectUris: ['https://app.example.com/auth/callback'],
 * });
 * ```
 */
export class ClientsClient {
  constructor(private readonly http: HttpClient) {}

  /**
   * List OIDC clients with optional filtering and pagination.
   * @param params - Filter and pagination options
   * @returns Clients array and pagination metadata
   */
  async list(params?: ListClientsParams): Promise<ListClientsResponse> {
    return this.http.get<ListClientsResponse>('/api/v1/clients', params as Record<string, unknown>);
  }

  /**
   * Get a single OIDC client by client_id.
   * @param clientId - The OIDC client identifier
   * @returns The client object
   * @throws {NotFoundError} If the client does not exist
   */
  async get(clientId: string): Promise<OidcClient> {
    const response = await this.http.get<ClientResponse>(`/api/v1/clients/${clientId}`);
    return response.client;
  }

  /**
   * Register a new OIDC client.
   * Returns the client AND the plaintext client secret (shown only once -- store it securely).
   * @param data - Client registration data
   * @returns The client object and the plaintext client secret
   * @throws {ConflictError} If a client with the same clientId already exists
   * @throws {ValidationError} If the input data is invalid
   */
  async register(data: RegisterClientData): Promise<ClientWithSecretResponse> {
    return this.http.post<ClientWithSecretResponse>('/api/v1/clients', data);
  }

  /**
   * Update an OIDC client. Uses PUT (full replacement, not partial update).
   * Note: clientId cannot be changed.
   * @param clientId - The OIDC client identifier
   * @param data - Updated client configuration
   * @returns The updated client object
   * @throws {NotFoundError} If the client does not exist
   * @throws {ValidationError} If the input data is invalid
   */
  async update(clientId: string, data: UpdateClientData): Promise<OidcClient> {
    const response = await this.http.put<ClientResponse>(`/api/v1/clients/${clientId}`, data);
    return response.client;
  }

  /**
   * Delete an OIDC client permanently.
   * @param clientId - The OIDC client identifier
   * @throws {NotFoundError} If the client does not exist
   */
  async delete(clientId: string): Promise<void> {
    await this.http.delete<void>(`/api/v1/clients/${clientId}`);
  }

  /**
   * Rotate the client secret. Returns the client AND the new plaintext secret.
   * The previous secret becomes invalid immediately.
   * @param clientId - The OIDC client identifier
   * @returns The client object and the new plaintext client secret
   * @throws {NotFoundError} If the client does not exist
   */
  async rotateSecret(clientId: string): Promise<ClientWithSecretResponse> {
    return this.http.post<ClientWithSecretResponse>(`/api/v1/clients/${clientId}/rotate-secret`);
  }
}
