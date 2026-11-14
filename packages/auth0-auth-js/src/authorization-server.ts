import { DomainValidationError } from './errors.js';

/**
 * Where the authorization server lives, as derived from the `domain` option.
 *
 * @internal
 */
export interface AuthorizationServer {
  /** Scheme, host and port, with no trailing slash. Base for the Auth0 endpoints (`/v2/logout`, `/mfa`, ...). */
  baseUrl: string;
  /** The issuer identifier, used for OIDC discovery. */
  issuer: URL;
  /** Key for the discovery cache. */
  cacheKey: string;
}

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Resolves the authorization server from the `domain` option.
 *
 * - A bare host (`example.auth0.com`, `localhost:3000`) is used as today: `https://${domain}`.
 * - A URL (`https://example.auth0.com`, `https://myorg.okta.com/oauth2/default`) keeps its scheme, host,
 *   port and path. A root issuer gets a trailing slash; a path issuer is kept as given, because the issuer
 *   in the discovery document is compared with it exactly.
 * - `http` is accepted only with `allowInsecureRequests`.
 *
 * @throws {DomainValidationError} For a URL with another scheme, `http` without `allowInsecureRequests`,
 *   a query, a fragment, or credentials.
 * @internal
 */
export function resolveAuthorizationServer(domain: string, allowInsecureRequests = false): AuthorizationServer {
  if (!SCHEME.test(domain)) {
    return {
      baseUrl: `https://${domain}`,
      issuer: new URL(`https://${domain}`),
      cacheKey: domain.toLowerCase(),
    };
  }

  let url: URL;
  try {
    url = new URL(domain);
  } catch {
    throw new DomainValidationError('domain is not a valid URL.');
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new DomainValidationError('domain must use https.');
  }
  if (url.protocol === 'http:' && !allowInsecureRequests) {
    throw new DomainValidationError('domain uses http, which requires allowInsecureRequests.');
  }
  if (url.search || url.hash) {
    throw new DomainValidationError('domain cannot contain a query or a fragment.');
  }
  if (url.username || url.password) {
    throw new DomainValidationError('domain cannot contain credentials.');
  }

  const issuer = new URL(url.pathname === '/' ? `${url.origin}/` : `${url.origin}${url.pathname}`);
  return { baseUrl: url.origin, issuer, cacheKey: issuer.href };
}
