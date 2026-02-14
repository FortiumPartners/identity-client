/**
 * Fortium Identity OIDC Client
 *
 * Core OIDC mechanics: PKCE, code exchange, token validation, logout.
 * Framework-agnostic — used directly or via the Fastify plugin.
 */
import type { FortiumClaims, OIDCState, TokenResult, RefreshResult } from './types.js';
export interface IdentityClientConfig {
    issuer: string;
    clientId: string;
    clientSecret: string;
}
export declare class IdentityClient {
    private issuer;
    private clientId;
    private clientSecret;
    private jwks;
    constructor(config: IdentityClientConfig);
    /**
     * Get JWKS key set for token validation (cached after first call).
     */
    private getJWKS;
    /**
     * Generate OIDC authorization URL with PKCE.
     * Returns the URL to redirect the user to and the OIDC state to store in a cookie.
     */
    generateAuthorizationUrl(redirectUri: string): Promise<{
        url: string;
        state: OIDCState;
    }>;
    /**
     * Exchange authorization code for tokens. Validates the ID token via JWKS.
     */
    exchangeCode(code: string, oidcState: OIDCState): Promise<TokenResult>;
    /**
     * Exchange refresh token for new tokens.
     */
    refreshToken(refreshToken: string): Promise<RefreshResult>;
    /**
     * Validate ID token using JWKS. Checks issuer, audience, nonce, and fortium_user_id.
     */
    validateIdToken(idToken: string, expectedNonce?: string): Promise<FortiumClaims>;
    /**
     * Validate access token (for API-to-API calls).
     */
    validateAccessToken(accessToken: string): Promise<FortiumClaims>;
    /**
     * Build RP-initiated logout URL.
     */
    getLogoutUrl(idTokenHint?: string, postLogoutRedirectUri?: string): string;
}
