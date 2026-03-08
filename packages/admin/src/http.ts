import type { AdminClientConfig, IdentityErrorResponse } from './types.js';
import {
  IdentityApiError,
  IdentityNetworkError,
  NotFoundError,
  ValidationError,
  ConflictError,
  UnauthorizedError,
  ForbiddenError,
  RateLimitError,
} from './errors.js';

export class HttpClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  constructor(config: AdminClientConfig) {
    if (!config.baseUrl || typeof config.baseUrl !== 'string') {
      throw new Error('baseUrl is required and must be a non-empty string');
    }
    if (!config.apiKey || typeof config.apiKey !== 'string') {
      throw new Error('apiKey is required and must be a non-empty string');
    }
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30_000;
  }

  /** Build full URL with query parameters */
  private buildUrl(path: string, params?: Record<string, unknown>): string {
    const url = new URL(path, this.baseUrl);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }
    return url.toString();
  }

  /** Common headers for all requests */
  private headers(hasBody: boolean): Record<string, string> {
    const h: Record<string, string> = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Accept': 'application/json',
    };
    if (hasBody) {
      h['Content-Type'] = 'application/json';
    }
    return h;
  }

  /** Execute fetch, handle errors */
  private async request<T>(
    method: string,
    path: string,
    options?: {
      params?: Record<string, unknown>;
      body?: unknown;
    },
  ): Promise<T> {
    const url = this.buildUrl(path, options?.params);
    const hasBody = options?.body !== undefined;

    try {
      const response = await fetch(url, {
        method,
        headers: this.headers(hasBody),
        body: hasBody ? JSON.stringify(options.body) : undefined,
        signal: AbortSignal.timeout(this.timeout),
      });

      // Handle 204 No Content (delete operations)
      if (response.status === 204) {
        return undefined as T;
      }

      const data = await response.json();

      if (!response.ok) {
        this.throwApiError(response.status, data as IdentityErrorResponse);
      }

      return data as T;
    } catch (err) {
      // Re-throw our own error types
      if (err instanceof IdentityApiError || err instanceof IdentityNetworkError) {
        throw err;
      }
      // Wrap network/timeout errors
      throw new IdentityNetworkError(
        `Request to ${method} ${path} failed: ${(err as Error).message}`,
        err as Error,
      );
    }
  }

  /** Map HTTP status to error class */
  private throwApiError(status: number, data: IdentityErrorResponse): never {
    const code = data?.error?.code ?? 'UNKNOWN_ERROR';
    const message = data?.error?.message ?? 'An unknown error occurred';

    switch (status) {
      case 400:
        throw new ValidationError(code, message);
      case 401:
        throw new UnauthorizedError(code, message);
      case 403:
        throw new ForbiddenError(code, message);
      case 404:
        throw new NotFoundError(code, message);
      case 409:
        throw new ConflictError(code, message);
      case 429:
        throw new RateLimitError(code, message);
      default:
        throw new IdentityApiError(status, code, message);
    }
  }

  // Public convenience methods used by sub-clients
  get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
    return this.request<T>('GET', path, { params });
  }

  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, { body });
  }

  patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('PATCH', path, { body });
  }

  put<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('PUT', path, { body });
  }

  delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }
}
