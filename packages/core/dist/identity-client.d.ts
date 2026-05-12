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
     * Request a narrow-audience access token via RFC 8693 token exchange.
     *
     * Used by the widget-token route to mint short-lived JWTs that downstream
     * services (e.g. ideas-api) can validate locally via JWKS. The calling
     * client must be allowlisted on Identity for the requested `audience`
     * via `oidc_clients.allowed_exchange_audiences` (migration 033).
     *
     * Trust model: `subjectUserId` is the user's Fortium user_id from the
     * authenticated session. The M2M client (this library, server-side)
     * vouches that this user is authenticated; Identity verifies the user
     * exists + is active but does NOT cryptographically verify caller
     * ownership of the user. See M2M_TOKEN_AUDIENCE.md in Identity repo.
     *
     * @param subjectUserId - Fortium user_id from session
     * @param audience - Requested audience (must be in client's allowlist)
     * @param timeoutMs - Hard timeout (default 5000ms)
     * @returns Token response from Identity (raw OAuth shape)
     * @throws Error with `.statusCode` (number) and `.oauthError` (string) on
     *   non-2xx response; or a generic Error on timeout/network failure.
     */
    requestWidgetToken(subjectUserId: string, audience: string, timeoutMs?: number): Promise<{
        access_token: string;
        token_type: string;
        expires_in: number;
        issued_token_type?: string;
        scope?: string;
    }>;
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
