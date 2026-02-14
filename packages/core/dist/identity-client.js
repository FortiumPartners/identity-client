/**
 * Fortium Identity OIDC Client
 *
 * Core OIDC mechanics: PKCE, code exchange, token validation, logout.
 * Framework-agnostic — used directly or via the Fastify plugin.
 */
import { webcrypto } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
// Node 18 doesn't expose crypto as a global in ESM
const cryptoImpl = globalThis.crypto ?? webcrypto;
const OIDC_ENDPOINTS = {
    authorization: '/oidc/auth',
    token: '/oidc/token',
    userinfo: '/oidc/me',
    jwks: '/.well-known/jwks.json',
    endSession: '/oidc/session/end',
};
const ENFORCED_SCOPES = 'openid profile email fortium offline_access';
export class IdentityClient {
    issuer;
    clientId;
    clientSecret;
    jwks = null;
    constructor(config) {
        this.issuer = config.issuer;
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret;
    }
    /**
     * Get JWKS key set for token validation (cached after first call).
     */
    getJWKS() {
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
    async generateAuthorizationUrl(redirectUri) {
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
            state: { state, nonce, codeVerifier, redirectUri },
        };
    }
    /**
     * Exchange authorization code for tokens. Validates the ID token via JWKS.
     */
    async exchangeCode(code, oidcState) {
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
        const tokens = (await response.json());
        const claims = await this.validateIdToken(tokens.id_token, oidcState.nonce);
        return {
            idToken: tokens.id_token,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
            claims,
        };
    }
    /**
     * Exchange refresh token for new tokens.
     */
    async refreshToken(refreshToken) {
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
            throw new Error(`Token refresh failed: ${response.status} - ${errorBody}`);
        }
        const tokens = (await response.json());
        return {
            idToken: tokens.id_token,
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
        };
    }
    /**
     * Validate ID token using JWKS. Checks issuer, audience, nonce, and fortium_user_id.
     */
    async validateIdToken(idToken, expectedNonce) {
        const { payload } = await jwtVerify(idToken, this.getJWKS(), {
            issuer: this.issuer,
            audience: this.clientId,
        });
        const claims = payload;
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
    async validateAccessToken(accessToken) {
        const { payload } = await jwtVerify(accessToken, this.getJWKS(), {
            issuer: this.issuer,
            audience: this.clientId,
        });
        return payload;
    }
    /**
     * Build RP-initiated logout URL.
     */
    getLogoutUrl(idTokenHint, postLogoutRedirectUri) {
        const logoutUrl = new URL(OIDC_ENDPOINTS.endSession, this.issuer);
        const params = new URLSearchParams();
        if (idTokenHint) {
            params.set('id_token_hint', idTokenHint);
        }
        if (postLogoutRedirectUri) {
            params.set('post_logout_redirect_uri', postLogoutRedirectUri);
        }
        logoutUrl.search = params.toString();
        return logoutUrl.toString();
    }
}
function base64URLEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
