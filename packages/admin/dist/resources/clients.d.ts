import type { HttpClient } from '../http.js';
import type { OidcClient, ListClientsParams, ListClientsResponse, ClientWithSecretResponse, RegisterClientData, UpdateClientData } from '../types.js';
export declare class ClientsClient {
    private readonly http;
    constructor(http: HttpClient);
    /** List OIDC clients with optional filtering and pagination. */
    list(params?: ListClientsParams): Promise<ListClientsResponse>;
    /** Get a single OIDC client by client_id. Throws NotFoundError if not found. */
    get(clientId: string): Promise<OidcClient>;
    /**
     * Register a new OIDC client.
     * Returns the client AND the plaintext client secret (shown only once).
     */
    register(data: RegisterClientData): Promise<ClientWithSecretResponse>;
    /**
     * Update an OIDC client. Uses PUT (not PATCH).
     * Note: clientId cannot be changed.
     */
    update(clientId: string, data: UpdateClientData): Promise<OidcClient>;
    /**
     * Delete an OIDC client. Returns void (API returns 204).
     * Throws NotFoundError if not found.
     */
    delete(clientId: string): Promise<void>;
    /**
     * Rotate the client secret. Returns the client AND the new plaintext secret.
     * The previous secret becomes invalid immediately.
     */
    rotateSecret(clientId: string): Promise<ClientWithSecretResponse>;
}
