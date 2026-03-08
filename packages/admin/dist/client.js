import { HttpClient } from './http.js';
/**
 * IdentityAdminClient -- main entry point for the admin API.
 * Resource sub-clients will be added in Sprint 2.
 */
export class IdentityAdminClient {
    http;
    constructor(config) {
        this.http = new HttpClient(config);
    }
}
