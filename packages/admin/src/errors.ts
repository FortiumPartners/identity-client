/**
 * Base error for all Identity API errors (non-network).
 * Thrown when the API returns an error response (4xx, 5xx).
 */
export class IdentityApiError extends Error {
  /** HTTP status code */
  readonly statusCode: number;
  /** Identity API error code (e.g., 'USER_NOT_FOUND') */
  readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.name = 'IdentityApiError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

export class NotFoundError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(404, code, message);
    this.name = 'NotFoundError';
  }
}

export class ValidationError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(400, code, message);
    this.name = 'ValidationError';
  }
}

export class ConflictError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(409, code, message);
    this.name = 'ConflictError';
  }
}

export class UnauthorizedError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(401, code, message);
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends IdentityApiError {
  constructor(code: string, message: string) {
    super(403, code, message);
    this.name = 'ForbiddenError';
  }
}

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
 */
export class IdentityNetworkError extends Error {
  override readonly cause: Error;

  constructor(message: string, cause: Error) {
    super(message);
    this.name = 'IdentityNetworkError';
    this.cause = cause;
  }
}
