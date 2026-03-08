/**
 * Base error for all Identity API errors (non-network).
 * Thrown when the API returns an error response (4xx, 5xx).
 */
export declare class IdentityApiError extends Error {
    /** HTTP status code */
    readonly statusCode: number;
    /** Identity API error code (e.g., 'USER_NOT_FOUND') */
    readonly code: string;
    constructor(statusCode: number, code: string, message: string);
}
export declare class NotFoundError extends IdentityApiError {
    constructor(code: string, message: string);
}
export declare class ValidationError extends IdentityApiError {
    constructor(code: string, message: string);
}
export declare class ConflictError extends IdentityApiError {
    constructor(code: string, message: string);
}
export declare class UnauthorizedError extends IdentityApiError {
    constructor(code: string, message: string);
}
export declare class ForbiddenError extends IdentityApiError {
    constructor(code: string, message: string);
}
export declare class RateLimitError extends IdentityApiError {
    constructor(code: string, message: string);
}
/**
 * Thrown for network-level failures (DNS, connection refused, timeout).
 * NOT a subclass of IdentityApiError -- these are infrastructure failures,
 * not API responses.
 */
export declare class IdentityNetworkError extends Error {
    readonly cause: Error;
    constructor(message: string, cause: Error);
}
