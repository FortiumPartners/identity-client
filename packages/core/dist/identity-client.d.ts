/**
 * Fortium Identity OIDC Client
 *
 * Core OIDC mechanics: PKCE, code exchange, token validation, logout.
 * Framework-agnostic — used directly or via the Fastify plugin.
 */
import type { FortiumClaims, OIDCState, TokenResult, RefreshResult } from './types.js';
/** OIDC `prompt` values generateAuthorizationUrl forwards. */
export declare const ALLOWED_PROMPTS: readonly string[];
/** How the client authenticates to the token endpoint (RFC 6749 section 2.3.1). */
export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post';
export interface IdentityClientConfig {
    issuer: string;
    clientId: string;
    clientSecret: string;
    /**
     * Token endpoint authentication method. Default `client_secret_basic`
     * (HTTP Basic, the method RFC 6749 section 2.3.1 requires servers to
     * support). Set `client_secret_post` for an app whose Identity
     * registration still says post.
     */
    tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
}
/** Extra authorization request parameters for generateAuthorizationUrl. */
export interface AuthorizationUrlOptions {
    /** OIDC `login_hint`, e.g. the email address to pre-fill. Dropped unless sanitizeLoginHint accepts it. */
    loginHint?: string;
    /** OIDC `prompt`. Dropped unless it is one of ALLOWED_PROMPTS. */
    prompt?: string;
}
export declare class IdentityClient {
    private issuer;
    private clientId;
    private clientSecret;
    private tokenEndpointAuthMethod;
    private jwks;
    constructor(config: IdentityClientConfig);
    /**
     * Headers and body for a token endpoint POST, authenticating the client with
     * the configured method.
     *
     * Basic (RFC 6749 section 2.3.1): the client_id and client_secret are each
     * form-urlencoded, joined with ':' and base64 encoded. Neither goes in the
     * body: client_id is only required there when the client does not
     * authenticate with Basic (section 4.1.3), and oidc-provider takes it from
     * the header.
     * Post: client_id and client_secret go in the body, which is what the SDK always sent before.
     */
    private tokenRequest;
    /**
     * Get JWKS key set for token validation (cached after first call).
     */
    private getJWKS;
    /**
     * Generate OIDC authorization URL with PKCE.
     * Returns the URL to redirect the user to and the OIDC state to store in a cookie.
     *
     * `opts.prompt` is appended only when it is one of ALLOWED_PROMPTS, and
     * `opts.loginHint` only when sanitizeLoginHint accepts it (trimmed). Any
     * other value is dropped. Without opts the URL is the same as before 1.5.0.
     */
    generateAuthorizationUrl(redirectUri: string, opts?: AuthorizationUrlOptions): Promise<{
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
    requestWidgetToken(subjectAccessToken: string, audience: string, timeoutMs?: number): Promise<{
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
     *
     * Without an id_token_hint, client_id is sent so the provider can still
     * validate post_logout_redirect_uri. With a hint it is left off: apps that
     * share a cookie domain can hold another client's ID token, and a client_id
     * that differs from the hint's audience makes the provider reject logout.
     */
    getLogoutUrl(idTokenHint?: string, postLogoutRedirectUri?: string): string;
}
