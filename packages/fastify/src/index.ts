export { identityPlugin } from './plugin.js';
export type { IdentityPluginOptions } from './plugin.js';
export { createM2MAuth } from './plugin.js';
export { requireAuth } from './middleware.js';
export type { RequireAuthOptions } from './middleware.js';

// Re-export core types for convenience
export type {
  FortiumClaims,
  OIDCState,
  SessionPayload,
  TokenResult,
  RefreshResult,
  M2MAuthOptions,
  M2MTokenPayload,
} from '@fortium/identity-client';
