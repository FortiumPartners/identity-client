import type { AdminClientConfig } from './types.js';
/**
 * IdentityAdminClient -- main entry point for the admin API.
 * Resource sub-clients will be added in Sprint 2.
 */
export declare class IdentityAdminClient {
    private readonly http;
    constructor(config: AdminClientConfig);
}
