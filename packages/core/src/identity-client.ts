/**
 * Fortium Identity OIDC Client
 *
 * Core OIDC mechanics: PKCE, code exchange, token validation, logout.
 * Framework-agnostic — used directly or via the Fastify plugin.
 */

import { webcrypto } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { FortiumClaims, OIDCState, TokenResponse, TokenResult, RefreshResult } from './types.js';

// Node 18 doesn't expose crypto as a global in ESM
const cryptoImpl = globalThis.crypto ?? webcrypto;

const OIDC_ENDPOINTS = {
  authorization: '/oidc/auth',
  token: '/oidc/token',
  userinfo: '/oidc/me',
  jwks: '/.well-known/jwks.json',
  endSession: '/oidc/session/end',
} as const;

const ENFORCED_SCOPES = 'openid profile email fortium offline_access';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface IdentityClientConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
}

export class IdentityClient {
  private issuer: string;
  private clientId: string;
  private clientSecret: string;
  private jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

  constructor(config: IdentityClientConfig) {
    this.issuer = config.issuer;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
  }

  /**
   * Get JWKS key set for token validation (cached after first call).
   */
  private getJWKS() {
    if (!this.jwks) {
      const jwksUri = new URL(OIDC_ENDPOINTS.jwks, this.issuer);
      this.jwks = createRemoteJWKSet(jwksUri);
    }
    return this.jwks;
  }

  /**
   * Generate OIDC authorization URL with PKCE.
   * Returns the URL to redirect the user to and the OIDC state to store in a cookie.
   */
  async generateAuthorizationUrl(redirectUri: string): Promise<{ url: string; state: OIDCState }> {
    const stateBytes = new Uint8Array(32);
    const nonceBytes = new Uint8Array(32);
    const verifierBytes = new Uint8Array(32);
    cryptoImpl.getRandomValues(stateBytes);
    cryptoImpl.getRandomValues(nonceBytes);
    cryptoImpl.getRandomValues(verifierBytes);

    const state = base64URLEncode(stateBytes);
    const nonce = base64URLEncode(nonceBytes);
    const codeVerifier = base64URLEncode(verifierBytes);

    const encoder = new TextEncoder();
    const hashBuffer = await cryptoImpl.subtle.digest('SHA-256', encoder.encode(codeVerifier));
    const codeChallenge = base64URLEncode(new Uint8Array(hashBuffer));

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: ENFORCED_SCOPES,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    const authUrl = new URL(OIDC_ENDPOINTS.authorization, this.issuer);
    authUrl.search = params.toString();

    return {
      url: authUrl.toString(),
      state: { state, nonce, codeVerifier, redirectUri, ts: Date.now() },
    };
  }

  /**
   * Exchange authorization code for tokens. Validates the ID token via JWKS.
   */
  async exchangeCode(code: string, oidcState: OIDCState): Promise<TokenResult> {
    const tokenUrl = new URL(OIDC_ENDPOINTS.token, this.issuer);

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: oidcState.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code_verifier: oidcState.codeVerifier,
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Token exchange failed: ${response.status} - ${errorBody}`);
    }

    const tokens = (await response.json()) as TokenResponse;
    const claims = await this.validateIdToken(tokens.id_token, oidcState.nonce);

    return {
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      expiresIn: tokens.expires_in,
      refreshToken: tokens.refresh_token,
      claims,
    };
  }

  /**
   * Exchange refresh token for new tokens.
   */
  async refreshToken(refreshToken: string): Promise<RefreshResult> {
    const tokenUrl = new URL(OIDC_ENDPOINTS.token, this.issuer);

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: refreshToken,
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      // statusCode tells a refused refresh (re-authenticate) from an
      // unreachable Identity (network errors throw without it).
      const err = new Error(`Token refresh failed: ${response.status} - ${errorBody}`) as Error & {
        statusCode: number;
      };
      err.statusCode = response.status;
      throw err;
    }

    const tokens = (await response.json()) as TokenResponse;

    return {
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      expiresIn: tokens.expires_in,
      refreshToken: tokens.refresh_token,
    };
  }

  /**
   * Request a narrow-audience access token via RFC 8693 token exchange.
   *
   * Used by the widget-token route to mint short-lived JWTs that downstream
   * services (e.g. ideas-api) can validate locally via JWKS. The calling
   * client must be allowlisted on Identity for the requested `audience`
   * via `oidc_clients.allowed_exchange_audiences` (migration 033).
   *
   * Trust model (Identity #63): the subject is the user's own Identity
   * access token, issued to this client. Identity resolves it and checks it
   * is valid, bound to the calling client, and on a live grant, so holding
   * the client secret alone no longer lets a caller mint a token for any
   * user. A bare user_id is refused here before any request is made.
   *
   * @param subjectAccessToken - The user's Identity access token (from the
   *   code exchange or a refresh), never a user_id
   * @param audience - Requested audience (must be in client's allowlist)
   * @param timeoutMs - Hard timeout (default 5000ms)
   * @returns Token response from Identity (raw OAuth shape)
   * @throws TypeError if `subjectAccessToken` is a UUID (a user_id);
   *   Error with `.statusCode` (number) and `.oauthError` (string) on
   *   non-2xx response; or a generic Error on timeout/network failure.
   */
  async requestWidgetToken(
    subjectAccessToken: string,
    audience: string,
    timeoutMs = 5000,
  ): Promise<{
    access_token: string;
    token_type: string;
    expires_in: number;
    issued_token_type?: string;
    scope?: string;
  }> {
    // Before 1.4.0 this argument was the user_id. Identity access tokens are
    // never UUID-shaped, so a UUID here is a caller that has not migrated.
    if (UUID_PATTERN.test(subjectAccessToken)) {
      throw new TypeError(
        'requestWidgetToken: subjectAccessToken must be the user\'s Identity access token, not a user_id',
      );
    }

    const tokenUrl = new URL(OIDC_ENDPOINTS.token, this.issuer);

    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subjectAccessToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      audience,
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      let oauthError = 'invalid_request';
      let errorDescription = `Token exchange failed: HTTP ${response.status}`;
      try {
        const errorBody = (await response.json()) as { error?: string; error_description?: string };
        oauthError = errorBody.error || oauthError;
        errorDescription = errorBody.error_description || errorDescription;
      } catch {
        // body wasn't JSON; keep defaults
      }
      const err = new Error(errorDescription) as Error & {
        statusCode: number;
        oauthError: string;
      };
      err.statusCode = response.status;
      err.oauthError = oauthError;
      throw err;
    }

    return response.json() as Promise<{
      access_token: string;
      token_type: string;
      expires_in: number;
      issued_token_type?: string;
      scope?: string;
    }>;
  }

  /**
   * Validate ID token using JWKS. Checks issuer, audience, nonce, and fortium_user_id.
   */
  async validateIdToken(idToken: string, expectedNonce?: string): Promise<FortiumClaims> {
    const { payload } = await jwtVerify(idToken, this.getJWKS(), {
      issuer: this.issuer,
      audience: this.clientId,
    });

    const claims = payload as FortiumClaims;

    if (expectedNonce && claims.nonce !== expectedNonce) {
      throw new Error('Nonce mismatch');
    }

    if (!claims.fortium_user_id) {
      throw new Error('Missing fortium_user_id claim');
    }

    return claims;
  }

  /**
   * Validate access token (for API-to-API calls).
   */
  async validateAccessToken(accessToken: string): Promise<FortiumClaims> {
    const { payload } = await jwtVerify(accessToken, this.getJWKS(), {
      issuer: this.issuer,
      audience: this.clientId,
    });

    return payload as FortiumClaims;
  }

  /**
   * Build RP-initiated logout URL.
   *
   * Without an id_token_hint, client_id is sent so the provider can still
   * validate post_logout_redirect_uri. With a hint it is left off: apps that
   * share a cookie domain can hold another client's ID token, and a client_id
   * that differs from the hint's audience makes the provider reject logout.
   */
  getLogoutUrl(idTokenHint?: string, postLogoutRedirectUri?: string): string {
    const logoutUrl = new URL(OIDC_ENDPOINTS.endSession, this.issuer);
    const params = new URLSearchParams();

    if (idTokenHint) {
      params.set('id_token_hint', idTokenHint);
    } else {
      params.set('client_id', this.clientId);
    }
    if (postLogoutRedirectUri) {
      params.set('post_logout_redirect_uri', postLogoutRedirectUri);
    }

    logoutUrl.search = params.toString();
    return logoutUrl.toString();
  }
}

function base64URLEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
