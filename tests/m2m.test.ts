import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import type { M2MAuthOptions, M2MTokenPayload } from '../packages/core/src/types';

// Mock jose — must include all named exports used transitively
const mockJwtVerify = jest.fn<any>();
const mockCreateRemoteJWKSet = jest.fn<any>().mockReturnValue('mock-jwks');

// Fake SignJWT builder (used by session.ts, not under test)
class MockSignJWT {
  constructor(_payload: any) {}
  setProtectedHeader() { return this; }
  setIssuedAt() { return this; }
  setExpirationTime() { return this; }
  setIssuer() { return this; }
  async sign() { return 'mock-session-jwt'; }
}

jest.unstable_mockModule('jose', () => ({
  jwtVerify: mockJwtVerify,
  createRemoteJWKSet: mockCreateRemoteJWKSet,
  SignJWT: MockSignJWT,
}));

describe('verifyM2MToken', () => {
  let verifyM2MToken: typeof import('../packages/core/src/m2m').verifyM2MToken;

  const defaultOpts: M2MAuthOptions = {
    issuer: 'https://identity.fortiumsoftware.com/oidc',
  };

  const validPayload: M2MTokenPayload = {
    sub: 'agent-max',
    iss: 'https://identity.fortiumsoftware.com/oidc',
    user_type: 'agent',
    fortium_user_id: 'agent-max',
    apps: [{ app_id: 'gateway', permissions: [] }],
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    mockJwtVerify.mockResolvedValue({ payload: validPayload });
    // Dynamic import after mock is set up
    const mod = await import('../packages/core/src/m2m');
    verifyM2MToken = mod.verifyM2MToken;
  });

  it('verifies a valid token and returns the payload', async () => {
    const result = await verifyM2MToken('valid-token', defaultOpts);

    expect(result).toEqual(validPayload);
    expect(mockJwtVerify).toHaveBeenCalledWith(
      'valid-token',
      'mock-jwks',
      { issuer: defaultOpts.issuer },
    );
  });

  it('passes audience to jwtVerify when specified', async () => {
    const opts: M2MAuthOptions = { ...defaultOpts, audience: 'atlas' };
    await verifyM2MToken('token', opts);

    expect(mockJwtVerify).toHaveBeenCalledWith(
      'token',
      'mock-jwks',
      { issuer: opts.issuer, audience: 'atlas' },
    );
  });

  it('does not pass audience when not specified', async () => {
    await verifyM2MToken('token', defaultOpts);

    const callArgs = mockJwtVerify.mock.calls[0]![2] as Record<string, unknown>;
    expect(callArgs).not.toHaveProperty('audience');
  });

  it('throws when jwtVerify fails', async () => {
    mockJwtVerify.mockRejectedValue(new Error('JWT expired'));

    await expect(verifyM2MToken('expired-token', defaultOpts))
      .rejects.toThrow('JWT expired');
  });

  describe('scope enforcement', () => {
    it('passes when token has all required scopes', async () => {
      mockJwtVerify.mockResolvedValue({
        payload: { ...validPayload, scope: 'read write admin' },
      });

      const opts: M2MAuthOptions = {
        ...defaultOpts,
        requiredScopes: ['read', 'write'],
      };

      const result = await verifyM2MToken('token', opts);
      expect(result.scope).toBe('read write admin');
    });

    it('throws when token is missing a required scope', async () => {
      mockJwtVerify.mockResolvedValue({
        payload: { ...validPayload, scope: 'read' },
      });

      const opts: M2MAuthOptions = {
        ...defaultOpts,
        requiredScopes: ['read', 'write'],
      };

      await expect(verifyM2MToken('token', opts))
        .rejects.toThrow('Missing scope: write');
    });

    it('throws when token has no scope claim but scopes are required', async () => {
      mockJwtVerify.mockResolvedValue({
        payload: { ...validPayload },
      });

      const opts: M2MAuthOptions = {
        ...defaultOpts,
        requiredScopes: ['read'],
      };

      await expect(verifyM2MToken('token', opts))
        .rejects.toThrow('Missing scope: read');
    });

    it('does not check scopes when requiredScopes is empty', async () => {
      const opts: M2MAuthOptions = {
        ...defaultOpts,
        requiredScopes: [],
      };

      const result = await verifyM2MToken('token', opts);
      expect(result).toEqual(validPayload);
    });
  });
});

describe('createM2MAuth (Express middleware)', () => {
  let createM2MAuth: typeof import('../packages/express/src/plugin').createM2MAuth;

  const defaultOpts: M2MAuthOptions = {
    issuer: 'https://identity.fortiumsoftware.com/oidc',
  };

  const validPayload: M2MTokenPayload = {
    sub: 'agent-max',
    user_type: 'agent',
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    mockJwtVerify.mockResolvedValue({ payload: validPayload });
    const mod = await import('../packages/express/src/plugin');
    createM2MAuth = mod.createM2MAuth;
  });

  function mockRes() {
    const res: any = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    return res;
  }

  it('rejects requests without Authorization header', async () => {
    const middleware = createM2MAuth(defaultOpts);
    const req = { headers: {} } as any;
    const res = mockRes();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Bearer token required' });
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects requests with non-Bearer authorization', async () => {
    const middleware = createM2MAuth(defaultOpts);
    const req = { headers: { authorization: 'Basic abc123' } } as any;
    const res = mockRes();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Bearer token required' });
    expect(next).not.toHaveBeenCalled();
  });

  it('attaches m2m payload to req and calls next on valid token', async () => {
    const middleware = createM2MAuth(defaultOpts);
    const req = { headers: { authorization: 'Bearer valid-jwt' } } as any;
    const res = mockRes();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(req.m2m).toEqual(validPayload);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('returns 401 when token verification fails', async () => {
    mockJwtVerify.mockRejectedValue(new Error('bad token'));

    const middleware = createM2MAuth(defaultOpts);
    const req = { headers: { authorization: 'Bearer bad-jwt' } } as any;
    const res = mockRes();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid token' });
    expect(next).not.toHaveBeenCalled();
  });
});
