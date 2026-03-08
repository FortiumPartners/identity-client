/**
 * Base error for all Identity API errors (non-network).
 * Thrown when the API returns an error response (4xx, 5xx).
 *
 * @example
 * ```typescript
 * try {
 *   await admin.users.get('nonexistent');
 * } catch (err) {
 *   if (err instanceof IdentityApiError) {
 *     console.log(err.statusCode, err.code, err.message);
 *   }
 * }
 * ```
 */
export class IdentityApiError extends Error {
  /** HTTP status code */
  readonly statusCode: number;
  /** Identity API error code (e.g., 'USER_NOT_FOUND') */
  readonly code: string;

  /**
   * @param statusCode - HTTP status code
   * @param code - Identity API error code
   * @param message - Human-readable error message
   */
  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.name = 'IdentityApiError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

/** Thrown when a requested resource is not found (HTTP 404). */
export class NotFoundError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(404, code, message);
    this.name = 'NotFoundError';
  }
}

/** Thrown when the request contains invalid input data (HTTP 400). */
export class ValidationError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(400, code, message);
    this.name = 'ValidationError';
  }
}

/** Thrown when a resource already exists or conflicts with existing state (HTTP 409). */
export class ConflictError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(409, code, message);
    this.name = 'ConflictError';
  }
}

/** Thrown when the API key is missing or invalid (HTTP 401). */
export class UnauthorizedError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(401, code, message);
    this.name = 'UnauthorizedError';
  }
}

/** Thrown when the API key lacks sufficient permissions for the operation (HTTP 403). */
export class ForbiddenError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(403, code, message);
    this.name = 'ForbiddenError';
  }
}

/** Thrown when too many requests have been made (HTTP 429). */
export class RateLimitError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(429, code, message);
    this.name = 'RateLimitError';
  }
}

/**
 * Thrown for network-level failures (DNS, connection refused, timeout).
 * NOT a subclass of IdentityApiError -- these are infrastructure failures,
 * not API responses.
 *
 * @example
 * ```typescript
 * try {
 *   await admin.users.list();
 * } catch (err) {
 *   if (err instanceof IdentityNetworkError) {
 *     console.log('Network failure:', err.cause);
 *   }
 * }
 * ```
 */
export class IdentityNetworkError extends Error {
  override readonly cause: Error;

  /**
   * @param message - Description of the network failure
   * @param cause - The original error that caused the failure
   */
  constructor(message: string, cause: Error) {
    super(message);
    this.name = 'IdentityNetworkError';
    this.cause = cause;
  }
}
