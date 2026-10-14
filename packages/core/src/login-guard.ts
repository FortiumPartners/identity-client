/**
 * Login guard shared by both plugins: after a callback ends in an error, /login
 * refuses to start another authorization request for a short window.
 *
 * Without it, an app whose /login restarts the flow on an error loops between
 * the app and Identity until the browser gives up. The guard lives in its own
 * short-lived signed cookie, not in the oidc_state flow cookie: that cookie may
 * be gone (it lives 10 minutes, and an invalid_callback has no matching attempt
 * to consume). Pure helpers, no I/O: the caller owns cookie read and write.
 */

import { CALLBACK_ERROR_CODES } from './callback-error.js';

/** How long, in seconds, a failed callback blocks the next /login by default. */
export const LOGIN_GUARD_DEFAULT_SECONDS = 30;

/**
 * What a guard can record: a registered OAuth error code, or one of the fixed
 * codes the plugins' own callback failures map to. Never free text: the
 * authorize hook's reason and the user's email stay out of the cookie.
 */
const GUARD_ERRORS: ReadonlySet<string> = new Set([
  ...CALLBACK_ERROR_CODES,
  'invalid_callback',
  'not_authorized',
  'callback_failed',
  'state_missing',
  'state_mismatch',
]);

/**
 * Cookie value recording that the last attempt ended in `error` at `now`.
 * Anything outside GUARD_ERRORS is stored as invalid_callback, so an
 * attacker-controlled `?error=` can only ever store an allowlisted code.
 */
export function serializeLoginGuard(error: unknown, now: number = Date.now()): string {
  const code = typeof error === 'string' && GUARD_ERRORS.has(error) ? error : 'invalid_callback';
  return JSON.stringify({ error: code, ts: now });
}

/**
 * The error code to send the browser to while the guard is fresh, or undefined
 * when there is no guard, it is malformed, or `windowSeconds` have passed since
 * it was set. The age is checked here as well as through the cookie's maxAge,
 * because a browser's clock decides when a cookie expires and the server's must
 * decide when the guard does. Never throws.
 */
export function activeLoginGuard(
  raw: string | null | undefined,
  windowSeconds: number,
  now: number = Date.now(),
): string | undefined {
  if (!raw) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const { error, ts } = parsed as { error?: unknown; ts?: unknown };
  if (typeof error !== 'string' || !GUARD_ERRORS.has(error)) return undefined;
  if (typeof ts !== 'number' || !Number.isFinite(ts)) return undefined;
  return now - ts < windowSeconds * 1000 ? error : undefined;
}

/** Headers for the page renderLoginGuardPage returns. */
export const LOGIN_GUARD_PAGE_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
});

/**
 * The plugin's own login route with `prompt=login`, built from the configured
 * callback URL (the login route is its sibling) and never from request input.
 * `returnTo` must already have passed sanitizeReturnTo; it is kept on the link
 * so a retry lands where the original request meant to.
 */
export function loginGuardRetryUrl(callbackUrl: string, returnTo?: string): string {
  // A trailing slash would make 'login' resolve under /callback/, not beside it.
  const base = new URL(callbackUrl);
  base.pathname = base.pathname.replace(/\/+$/, '');
  const url = new URL('login', base);
  url.search = '';
  url.searchParams.set('prompt', 'login');
  if (returnTo) url.searchParams.set('returnTo', returnTo);
  return url.toString();
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * The page /login answers with, instead of a redirect, while the guard is
 * fresh. It ends the redirect chain whatever the app's own /login does. No
 * script, no style, no external resource, so any Content-Security-Policy
 * allows it. `error` and `retryHref` are escaped here as well as sanitized by
 * the caller.
 */
export function renderLoginGuardPage(error: string, retryHref: string): string {
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>Sign-in did not complete</title>',
    '</head>',
    '<body>',
    '<h1>Sign-in did not complete</h1>',
    `<p>The last sign-in attempt ended with the error <code>${escapeHtml(error)}</code>.</p>`,
    `<p><a href="${escapeHtml(retryHref)}">Try again</a></p>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

/**
 * The codes OIDC Core section 3.1.2.6 defines as the expected answer to
 * `prompt=none`: the user has to interact. The client's correct next step is an
 * interactive authorization request, so they must not block one.
 */
const INTERACTION_NEEDED: ReadonlySet<string> = new Set([
  'login_required',
  'interaction_required',
  'consent_required',
  'account_selection_required',
]);

/**
 * Does a fresh guard recording `error` block a /login with this `prompt`?
 *
 * - An explicit action (`login`, `select_account`) is never blocked.
 * - After an interaction-needed code, only `prompt=none` is blocked, because it
 *   would get the same answer. Every other request is the interactive step the
 *   spec calls for.
 * - After any other error, every other request is blocked.
 */
export function loginGuardBlocks(error: string, prompt: unknown): boolean {
  if (isExplicitLoginPrompt(prompt)) return false;
  if (INTERACTION_NEEDED.has(error)) return prompt === 'none';
  return true;
}

/**
 * Is this `prompt` an explicit user action that starts a fresh attempt?
 * `login` and `select_account` (OIDC Core section 3.1.2.1) ask the user to
 * authenticate or choose an account again, so they are never a loop.
 */
export function isExplicitLoginPrompt(prompt: unknown): boolean {
  return prompt === 'login' || prompt === 'select_account';
}
