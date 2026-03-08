import type { AdminClientConfig } from './types.js';
export declare class HttpClient {
    private readonly baseUrl;
    private readonly apiKey;
    private readonly timeout;
    constructor(config: AdminClientConfig);
    /** Build full URL with query parameters */
    private buildUrl;
    /** Common headers for all requests */
    private headers;
    /** Execute fetch, handle errors */
    private request;
    /** Map HTTP status to error class */
    private throwApiError;
    get<T>(path: string, params?: Record<string, unknown>): Promise<T>;
    post<T>(path: string, body?: unknown): Promise<T>;
    patch<T>(path: string, body: unknown): Promise<T>;
    put<T>(path: string, body: unknown): Promise<T>;
    delete<T>(path: string): Promise<T>;
}
