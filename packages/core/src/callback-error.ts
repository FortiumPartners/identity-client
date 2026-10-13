/**
 * OAuth / OIDC error codes an authorization server can return on the redirect
 * to /callback, shared by both plugins.
 */

/**
 * RFC 6749 section 4.1.2.1 and OIDC Core section 3.1.2.6. A code outside this
 * list is not forwarded, so a crafted `?error=` cannot put its own text in the
 * app's /login URL.
 */
export const CALLBACK_ERROR_CODES: ReadonlySet<string> = new Set([
  // RFC 6749 section 4.1.2.1
  'invalid_request',
  'unauthorized_client',
  'access_denied',
  'unsupported_response_type',
  'invalid_scope',
  'server_error',
  'temporarily_unavailable',
  // OIDC Core section 3.1.2.6
  'interaction_required',
  'login_required',
  'account_selection_required',
  'consent_required',
  'invalid_request_uri',
  'invalid_request_object',
  'request_not_supported',
  'request_uri_not_supported',
  'registration_not_supported',
]);

/**
 * Returns the error code to forward as `/login?error=<code>`, or undefined when
 * the value is not a registered code (not a string, repeated, or unknown).
 * `error_description` and `error_uri` have no counterpart here: they are never
 * read, so they cannot reach a URL.
 */
export function sanitizeCallbackError(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  return CALLBACK_ERROR_CODES.has(raw) ? raw : undefined;
}
