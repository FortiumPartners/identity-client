import type { AdminClientConfig } from './types.js';
import { HttpClient } from './http.js';

/**
 * IdentityAdminClient -- main entry point for the admin API.
 * Resource sub-clients will be added in Sprint 2.
 */
export class IdentityAdminClient {
  private readonly http: HttpClient;

  constructor(config: AdminClientConfig) {
    this.http = new HttpClient(config);
  }
}
