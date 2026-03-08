import { describe, it, expect } from '@jest/globals';
import {
  IdentityApiError,
  NotFoundError,
  ValidationError,
  ConflictError,
  UnauthorizedError,
  ForbiddenError,
  RateLimitError,
  IdentityNetworkError,
} from '@fortium/identity-client/admin';

describe('Error hierarchy', () => {
  describe('IdentityApiError', () => {
    it('sets statusCode, code, and message', () => {
      const err = new IdentityApiError(500, 'INTERNAL_ERROR', 'Something broke');
      expect(err.statusCode).toBe(500);
      expect(err.code).toBe('INTERNAL_ERROR');
      expect(err.message).toBe('Something broke');
      expect(err.name).toBe('IdentityApiError');
    });

    it('is an instance of Error', () => {
      const err = new IdentityApiError(500, 'INTERNAL_ERROR', 'fail');
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(IdentityApiError);
    });
  });

  describe('NotFoundError', () => {
    it('has statusCode 404', () => {
      const err = new NotFoundError('USER_NOT_FOUND', 'User not found');
      expect(err.statusCode).toBe(404);
      expect(err.code).toBe('USER_NOT_FOUND');
      expect(err.name).toBe('NotFoundError');
    });

    it('is instanceof IdentityApiError', () => {
      const err = new NotFoundError('USER_NOT_FOUND', 'nope');
      expect(err).toBeInstanceOf(IdentityApiError);
      expect(err).toBeInstanceOf(NotFoundError);
    });
  });

  describe('ValidationError', () => {
    it('has statusCode 400', () => {
      const err = new ValidationError('VALIDATION_ERROR', 'Bad input');
      expect(err.statusCode).toBe(400);
      expect(err.code).toBe('VALIDATION_ERROR');
      expect(err.name).toBe('ValidationError');
    });

    it('is instanceof IdentityApiError', () => {
      expect(new ValidationError('V', 'x')).toBeInstanceOf(IdentityApiError);
    });
  });

  describe('ConflictError', () => {
    it('has statusCode 409', () => {
      const err = new ConflictError('USER_EXISTS', 'Already exists');
      expect(err.statusCode).toBe(409);
      expect(err.name).toBe('ConflictError');
    });

    it('is instanceof IdentityApiError', () => {
      expect(new ConflictError('C', 'x')).toBeInstanceOf(IdentityApiError);
    });
  });

  describe('UnauthorizedError', () => {
    it('has statusCode 401', () => {
      const err = new UnauthorizedError('UNAUTHORIZED', 'Bad token');
      expect(err.statusCode).toBe(401);
      expect(err.name).toBe('UnauthorizedError');
    });

    it('is instanceof IdentityApiError', () => {
      expect(new UnauthorizedError('U', 'x')).toBeInstanceOf(IdentityApiError);
    });
  });

  describe('ForbiddenError', () => {
    it('has statusCode 403', () => {
      const err = new ForbiddenError('FORBIDDEN', 'Not allowed');
      expect(err.statusCode).toBe(403);
      expect(err.name).toBe('ForbiddenError');
    });

    it('is instanceof IdentityApiError', () => {
      expect(new ForbiddenError('F', 'x')).toBeInstanceOf(IdentityApiError);
    });
  });

  describe('RateLimitError', () => {
    it('has statusCode 429', () => {
      const err = new RateLimitError('RATE_LIMIT_EXCEEDED', 'Slow down');
      expect(err.statusCode).toBe(429);
      expect(err.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(err.name).toBe('RateLimitError');
    });

    it('is instanceof IdentityApiError', () => {
      expect(new RateLimitError('R', 'x')).toBeInstanceOf(IdentityApiError);
    });
  });

  describe('IdentityNetworkError', () => {
    it('wraps an underlying cause', () => {
      const cause = new TypeError('fetch failed');
      const err = new IdentityNetworkError('Connection refused', cause);
      expect(err.message).toBe('Connection refused');
      expect(err.cause).toBe(cause);
      expect(err.name).toBe('IdentityNetworkError');
    });

    it('is instanceof Error but NOT IdentityApiError', () => {
      const cause = new Error('timeout');
      const err = new IdentityNetworkError('timed out', cause);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(IdentityApiError);
    });
  });
});
