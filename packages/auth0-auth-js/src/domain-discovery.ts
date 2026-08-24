import { LruCache } from './lru-cache.js';
import { createTelemetryFetch, type TelemetryConfig } from './telemetry.js';

const OIDC_ISSUER_REL = 'http://openid.net/specs/connect/1.0/issuer';

const cache = new LruCache<string, boolean>(1000, 60_000);

export interface IsFederatedDomainOptions {
  customFetch?: typeof fetch;
  telemetry?: TelemetryConfig;
}

/**
 * Checks whether an email domain is managed for enterprise SSO on the given Auth0 tenant
 * by calling the WebFinger endpoint.
 *
 * This is a routing hint, not a security control. Always validate the returned ID token
 * and `org_id` claim after the Auth0 callback.
 *
 * @param auth0Domain - The Auth0 tenant domain (e.g. 'your-tenant.auth0.com')
 * @param emailDomain - The email domain to check (e.g. 'acmecorp.com')
 * @param options - Optional customFetch and telemetry configuration
 * @returns true if the domain is federated, false otherwise. Never throws.
 */
export async function isFederatedDomain(
  auth0Domain: string,
  emailDomain: string,
  options?: IsFederatedDomainOptions
): Promise<boolean> {
  const normalizedDomain = emailDomain.toLowerCase();
  const key = `${auth0Domain}|${normalizedDomain}`;

  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  try {
    const url = new URL(`https://${auth0Domain}/.well-known/webfinger`);
    url.searchParams.set('resource', `urn:auth0:discovery:domain:${normalizedDomain}`);
    url.searchParams.set('rel', OIDC_ISSUER_REL);

    let fetchFn: typeof fetch = options?.customFetch ?? globalThis.fetch;
    if (options?.telemetry && options.telemetry.enabled !== false) {
      fetchFn = createTelemetryFetch(fetchFn, options.telemetry);
    }
    const res = await fetchFn(url.toString());

    if (res.ok) {
      const body = await res.json();
      const managed =
        Array.isArray(body.links) &&
        body.links.some((l: { rel?: string }) => l.rel === OIDC_ISSUER_REL);
      if (managed) {
        cache.set(key, true);
        return true;
      }
      // 200 but no matching rel — do not cache
      return false;
    }

    if (res.status === 404) {
      cache.set(key, false, 15_000);  // shorter TTL for newly-configured domains to appear quickly
      return false;
    }

    if (res.status === 429) {
      console.warn('[Auth0] isFederatedDomain: rate limit hit (429)');
      return false;
    }

    // 403 (endpoint disabled) or other non-ok status
    return false;
  } catch {
    // Network error / 5xx
    return false;
  }
}
