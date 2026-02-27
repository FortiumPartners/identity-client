import type { JWTPayload } from 'jose';

/**
 * Fortium Identity custom claims included in ID tokens.
 */
export interface FortiumClaims extends JWTPayload {
  fortium_user_id: string;
  email: string;
  email_verified: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  orgs?: Array<{
    org_id: string;
    name: string;
    role: string;
  }>;
  apps?: Array<{
    app_id: string;
    permissions: string[];
  }>;
}

/**
 * PKCE state stored in signed cookie during auth flow.
 */
export interface OIDCState {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
}

/**
 * Raw token response from the Identity /oidc/token endpoint.
 */
export interface TokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
}

/**
 * Processed result from code exchange or token refresh.
 */
export interface TokenResult {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  claims: FortiumClaims;
}

/**
 * Result from token refresh (claims not always available).
 */
export interface RefreshResult {
  idToken?: string;
  accessToken: string;
  refreshToken?: string;
}

/**
 * Base session payload stored in session JWT.
 * Apps extend this via the authorize hook return value.
 */
export interface SessionPayload {
  fortiumUserId: string;
  email: string;
  [key: string]: unknown;
}

/**
 * Decoded payload from an Identity-issued M2M (client_credentials) JWT.
 */
export interface M2MTokenPayload extends JWTPayload {
  sub: string;
  fortium_user_id?: string;
  user_type?: string;
  owner_id?: string;
  apps?: Array<{ app_id: string; permissions: string[] }>;
  orgs?: Array<{ org_id: string; name: string; role: string }>;
}

/**
 * Options for M2M token verification middleware.
 */
export interface M2MAuthOptions {
  /** Identity issuer URL (e.g., https://identity.fortiumsoftware.com/oidc) */
  issuer: string;
  /** Expected audience claim (usually the app's client_id) */
  audience?: string;
  /** Required scopes — rejects tokens missing any of these */
  requiredScopes?: string[];
}
