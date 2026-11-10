import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, customFetch, decodeJwt, decodeProtectedHeader } from 'jose';
import { AuthClient, TokenForConnectionError, MissingClientAuthError } from '@auth0/auth0-auth-js';
import {
  AccessTokenForConnectionOptions,
  ApiClientOptions,
  ConnectionTokenSet,
  DPoPOptions,
  DomainsResolver,
  DomainsResolverContext,
  ExchangeProfileOptions,
  OnBehalfOfTokenOptions,
  OnBehalfOfTokenResult,
  PoppySession,
  ScopeMatching,
  TokenExchangeProfileResult,
  VerifiedPoppyRequest,
  VerifyAccessTokenOptions,
  VerifyPoppyRequestOptions,
  VerifiedAccessTokenClaims,
} from './types.js';
import { TokenSet } from './token-store.js';
import {
  AuthError,
  InvalidConfigurationError,
  InvalidDpopProofError,
  InvalidRequestError,
  MissingOrganizationError,
  MissingRequiredArgumentError,
  OrganizationNotAllowedError,
  VerifyAccessTokenError,
} from './errors.js';
import {
  isIndexedTokenStore,
  normalizeScopes,
  type OnBehalfOfTokenContext,
  type TokenStore,
  type VerifiedToken,
} from './token-store.js';
import { hasUnkeyableClaims, type OboCacheKeyIdentity } from './obo-cache-key.js';
import {
  TOKEN_EXPIRY_LEEWAY_SECONDS,
  readOboCachedToken,
  writeOboCachedToken,
  type OboCacheAccess,
} from './obo-cache.js';
import { ALLOWED_DPOP_ALGORITHMS, buildChallenges, verifyDpopProof } from './dpop-api.js';
import { LruCache } from './lru-cache.js';
import { AgentMetadataFetcher } from './poppy/agent-metadata.js';
import { DEFAULT_DELEGATION_CACHE_MAX_ENTRIES } from './poppy/constants.js';
import { DelegationVerifier } from './poppy/delegation.js';
import { resolvePoppyOptions, type ResolvedPoppyOptions } from './poppy/options.js';
import { verifyPoppyRequest as runPoppyPipeline, type PoppyPipeline } from './poppy/verify-poppy-request.js';

const OBO_ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * @category Getting Started
 */
export class ApiClient {
  readonly #serverMetadataByDomain: LruCache<oauth.AuthorizationServer>;
  readonly #options: ApiClientOptions;
  readonly #jwksByUri: LruCache<ReturnType<typeof createRemoteJWKSet>>;
  readonly #domains?: string[] | DomainsResolver;
  readonly #algorithms: string[];
  readonly #defaultDomainUrl?: string;
  readonly #authClient: AuthClient | undefined;
  // Snapshots of the options the On Behalf Of cache depends on. `#options` keeps a
  // reference to the caller's object, so reading these from it per request would let a
  // later mutation change behaviour after construction-time validation had passed. The
  // cache key binds a cached token to the client that exchanged it, and `#authClient` is
  // built once from the construction-time client id; a mutated client id in the key would
  // let two different exchanging clients share one cache entry.
  readonly #scopeMatching: ScopeMatching;
  readonly #clientId: string | undefined;
  readonly #audience: string | undefined;
  // Whether any client authentication was configured. The underlying `AuthClient` is
  // built whenever a client id is present, so its existence says nothing about whether an
  // exchange could succeed. Every exchange needs a client secret or an assertion signing
  // key, so a client without either is refused before any verification or cache access.
  readonly #hasClientAuth: boolean;
  // Claims objects this instance returned from `verifyAccessToken`, mapped to a record of
  // the token each was verified from and a copy of the claims as they were at that moment.
  // A caller-supplied `context.verified` is only trusted when its claims object is in
  // here, so claims can neither be forged nor borrowed from a different client, audience
  // or tenant. Keyed on object identity, so a clone or a deserialized copy is deliberately
  // not recognised. The stored copy, not the caller's object, is what the cache key is
  // derived from, so mutating a claims object after verification has no effect.
  readonly #verifiedClaims = new WeakMap<object, { accessToken: string; claims: VerifiedAccessTokenClaims }>();
  readonly #organizationPolicy: 'required' | 'allow';
  readonly #organizationAllowlist?: ReadonlySet<string>;
  // Gives the resolved `poppy` options to `verifyPoppyRequest`. Set at the end of the constructor.
  readonly #resolvePoppy: () => ResolvedPoppyOptions;
  // Built by `#poppyPipeline()` on first use.
  #poppyPipelineCache?: PoppyPipeline;

  /**
   * @category Constructor
   */
  constructor(options: ApiClientOptions) {
    if (options.dpop !== undefined && (typeof options.dpop !== 'object' || options.dpop === null)) {
      throw new InvalidConfigurationError('Invalid DPoP configuration: "dpop" must be an object');
    }

    if (options.dpop) {
      const { mode, iatOffset, iatLeeway } = options.dpop;
      if (mode !== undefined && !['allowed', 'required', 'disabled'].includes(mode)) {
        throw new InvalidConfigurationError(
          'Invalid DPoP configuration: "mode" must be allowed, required, or disabled'
        );
      }
      if (iatOffset !== undefined) {
        if (!Number.isFinite(iatOffset)) {
          throw new InvalidConfigurationError('Invalid DPoP configuration: "iatOffset" must be a number');
        }
        if (iatOffset < 0) {
          throw new InvalidConfigurationError('Invalid DPoP configuration: "iatOffset" must be a non-negative number');
        }
      }
      if (iatLeeway !== undefined) {
        if (!Number.isFinite(iatLeeway)) {
          throw new InvalidConfigurationError('Invalid DPoP configuration: "iatLeeway" must be a number');
        }
        if (iatLeeway < 0) {
          throw new InvalidConfigurationError('Invalid DPoP configuration: "iatLeeway" must be a non-negative number');
        }
      }
    }

    if (
      options.scopeMatching !== undefined &&
      options.scopeMatching !== 'strict' &&
      options.scopeMatching !== 'non_strict'
    ) {
      throw new InvalidConfigurationError(
        'Invalid scope matching configuration: "scopeMatching" must be "strict" or "non_strict"'
      );
    }

    const discoveryCacheConfig = options.discoveryCache ?? {};
    const ttlSeconds = discoveryCacheConfig.ttl ?? 600;
    if (!Number.isFinite(ttlSeconds)) {
      throw new InvalidConfigurationError('Invalid discoveryCache configuration: "ttl" must be a number');
    }
    if (ttlSeconds < 0) {
      throw new InvalidConfigurationError('Invalid discoveryCache configuration: "ttl" must be a non-negative number');
    }
    const cacheTtlMs = ttlSeconds * 1000;

    const maxEntries = discoveryCacheConfig.maxEntries ?? 100;
    if (!Number.isFinite(maxEntries)) {
      throw new InvalidConfigurationError('Invalid discoveryCache configuration: "maxEntries" must be a number');
    }
    if (maxEntries < 0) {
      throw new InvalidConfigurationError(
        'Invalid discoveryCache configuration: "maxEntries" must be a non-negative number'
      );
    }

    this.#serverMetadataByDomain = new LruCache<oauth.AuthorizationServer>(cacheTtlMs, maxEntries);
    this.#jwksByUri = new LruCache<ReturnType<typeof createRemoteJWKSet>>(cacheTtlMs, maxEntries);

    this.#options = options;
    this.#scopeMatching = options.scopeMatching ?? 'strict';
    this.#clientId = options.clientId;
    this.#audience = options.audience;
    this.#hasClientAuth = !!options.clientSecret || !!options.clientAssertionSigningKey;

    if (
      options.organizationPolicy !== undefined &&
      options.organizationPolicy !== 'required' &&
      options.organizationPolicy !== 'allow'
    ) {
      throw new InvalidConfigurationError(
        'Invalid organization configuration: "organizationPolicy" must be "required" or "allow".'
      );
    }

    this.#organizationPolicy = options.organizationPolicy ?? 'allow';

    if (options.organizationId !== undefined) {
      if (options.organizationPolicy !== 'required') {
        throw new InvalidConfigurationError(
          'Invalid organization configuration: "organizationId" is only valid when "organizationPolicy" is "required".'
        );
      }
      const ids: unknown[] = Array.isArray(options.organizationId)
        ? Array.from(options.organizationId as unknown[])
        : [options.organizationId];
      // An untrimmed id is rejected rather than trimmed: it can never equal an
      // `org_id` claim, so accepting it would silently reject every token.
      const valid = ids.length > 0 && ids.every((id) => typeof id === 'string' && id !== '' && id === id.trim());
      if (!valid) {
        throw new InvalidConfigurationError(
          'Invalid organization configuration: "organizationId" must be an organization id, or a non-empty array of organization ids, with no empty or untrimmed values.'
        );
      }
      // Snapshot the allowlist so later mutation of the caller's options object
      // cannot widen or disable what was validated here.
      this.#organizationAllowlist = new Set(ids as string[]);
    }

    if (options.domain !== undefined) {
      try {
        this.#defaultDomainUrl = normalizeDomain(options.domain);
      } catch (error) {
        const message = (error as Error).message;
        throw new InvalidConfigurationError(`Invalid domain configuration: ${message}`);
      }
    }

    if (options.domains !== undefined) {
      if (Array.isArray(options.domains)) {
        if (options.domains.length === 0) {
          throw new InvalidConfigurationError('Invalid domains configuration: "domains" must not be empty');
        }
        const normalized = options.domains.map((domain) => {
          try {
            return normalizeDomain(domain);
          } catch (error) {
            const message = (error as Error).message;
            throw new InvalidConfigurationError(`Invalid domains configuration: ${message}`);
          }
        });
        this.#domains = Array.from(new Set(normalized));
      } else if (typeof options.domains === 'function') {
        this.#domains = options.domains;
      } else {
        throw new InvalidConfigurationError('Invalid domains configuration: "domains" must be an array or a function');
      }
    }

    this.#algorithms = normalizeAlgorithms(options.algorithms);

    if (!this.#defaultDomainUrl && this.#domains === undefined) {
      throw new MissingRequiredArgumentError('domain or domains');
    }

    if (options.clientId) {
      if (!options.domain) {
        throw new MissingRequiredArgumentError('domain');
      }
      this.#authClient = new AuthClient({
        domain: options.domain,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        clientAssertionSigningKey: options.clientAssertionSigningKey,
        clientAssertionSigningAlg: options.clientAssertionSigningAlg,
        customFetch: options.customFetch,
      });
    }

    if (!this.#audience) {
      throw new MissingRequiredArgumentError('audience');
    }

    if (options.poppy !== undefined) {
      // Resolved now, so a mistake in the option throws here.
      const poppy = resolvePoppyOptions(options);
      this.#resolvePoppy = () => poppy;
    } else {
      // Resolved on first use, with every setting at its default. It reads a copy of the options: `#options` is the
      // caller's object, and a change to its `customFetch` after construction must not change how agents are fetched.
      const defaults: ApiClientOptions = { ...options, poppy: {} };
      this.#resolvePoppy = () => resolvePoppyOptions(defaults);
    }
  }

  /**
   * Initialized the SDK by performing Metadata Discovery.
   */
  async #discoverDomain(domain: string) {
    const serverMetadata = await this.#serverMetadataByDomain.getOrSet(domain, async () => {
      const issuer = new URL(domain);
      const response = await oauth.discoveryRequest(issuer, {
        [oauth.customFetch]: this.#options.customFetch,
      });
      return oauth.processDiscoveryResponse(issuer, response);
    });

    return { serverMetadata };
  }

  /**
   * Verifies the provided access token against the ApiClient's configured audience.
   *
   * This method validates the JWT signature using the Auth0 tenant's JWKS and verifies
   * standard claims including issuer, expiration, and issued-at time. The audience claim
   * is verified against the audience configured when constructing the ApiClient.
   *
   * DPoP support:
   * - `dpop.mode` controls behavior: `allowed` (default) accepts Bearer or DPoP; `required` enforces DPoP; `disabled` ignores DPoP.
   * - When validating a DPoP-bound token, you must provide `scheme: 'dpop'`, the `dpopProof` header value, and the actual `httpMethod`/`httpUrl` used for the request.
   * - Bearer tokens omit DPoP params; DPoP params are validated together and proof binding is enforced.
   *
   * @param options Options containing the access token and optional required claims.
   * @see README.md and EXAMPLES.md for usage in allowed/required/disabled modes.
   * @returns Promise resolving to the verified token payload containing all JWT claims.
   * @throws {VerifyAccessTokenError} When verification fails due to invalid signature,
   *                                   expired token, mismatched audience, or missing required claims.
   * @category Token Verification
   *
   * @example
   * ```typescript
   * @example Bearer token validation
   * const apiClient = new ApiClient({
   *   domain: 'example.auth0.com',
   *   audience: 'https://api.example.com', // This audience is used for verification
   * });
   * const payload = await apiClient.verifyAccessToken({
   *   accessToken: 'eyJhbGc...',
   * });
   *
   * @example DPoP-bound token validation (allowed/required mode)
   * const apiClient = new ApiClient({
   *   domain: 'example.auth0.com',
   *   audience: 'https://api.example.com',
   *   dpop: { mode: 'required' }, // default is 'allowed'
   * });
   * const dpopPayload = await apiClient.verifyAccessToken({
   *   accessToken: 'eyJhbGc...',              // JWT with cnf.jkt claim
   *   scheme: 'dpop',
   *   dpopProof: 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3A...', // value from DPoP header
   *   httpMethod: 'GET',                      // actual request method
   *   httpUrl: 'https://api.example.com/resource', // actual request URL
   * });
   * ```
   */
  async verifyAccessToken(options: VerifyAccessTokenOptions): Promise<VerifiedAccessTokenClaims> {
    const mode: NonNullable<DPoPOptions['mode']> = this.#options.dpop?.mode ?? 'allowed';
    // Default timing options
    const iatOffset = this.#options.dpop?.iatOffset ?? 300;
    const iatLeeway = this.#options.dpop?.iatLeeway ?? 30;

    // Normalize scheme to lowercase; default to 'bearer' if not provided.
    const scheme = (options.scheme ?? 'bearer').toLowerCase();
    const dpopProof = options.dpopProof;
    const httpMethod = options.httpMethod;
    const httpUrl = options.httpUrl;
    const hasDpopParams =
      dpopProof !== undefined || httpMethod !== undefined || (this.#domains === undefined && httpUrl !== undefined);

    // When DPoP is enabled, only 'bearer' and 'dpop' schemes are allowed.
    if (mode !== 'disabled' && scheme && !['bearer', 'dpop'].includes(scheme)) {
      const err = new InvalidRequestError('');
      err.cause = { code: 'invalid_auth_scheme' };
      throw this.#addChallenges(err, mode, scheme, { includeError: false });
    }

    // When DPoP is required, only 'dpop' scheme is allowed.
    if (mode === 'required' && scheme !== 'dpop') {
      const err = new InvalidRequestError('');
      err.cause = { code: 'invalid_auth_scheme' };
      throw this.#addChallenges(err, mode, scheme, {
        includeError: false,
        dpopSpecific: true,
      });
    }

    // When DPoP is disabled, only 'bearer' scheme is allowed.
    if (mode === 'disabled' && scheme && scheme !== 'bearer') {
      const err = new InvalidRequestError('');
      err.cause = { code: 'invalid_auth_scheme' };
      throw this.#addChallenges(err, mode, scheme, { includeError: false });
    }

    // When `scheme` is not provided, but DPoP-only parameters are present.
    if (mode !== 'disabled' && hasDpopParams && options.scheme === undefined) {
      const err = new InvalidRequestError('');
      err.cause = { code: 'invalid_auth_scheme' };
      throw this.#addChallenges(err, mode, scheme, {
        includeError: false,
        dpopSpecific: true,
      });
    }

    // Access token must always be present.
    if (typeof options.accessToken !== 'string' || !options.accessToken) {
      throw this.#addChallenges(new VerifyAccessTokenError(''), mode, scheme, { includeError: false });
    }

    const accessToken = options.accessToken;
    const domains = this.#domains;
    let jwks: ReturnType<typeof createRemoteJWKSet>;
    let issuerForVerify = '';
    let unverifiedIss: string | undefined;
    let alg: string | undefined;

    const defaultDomainUrl = this.#defaultDomainUrl;

    try {
      try {
        const header = decodeProtectedHeader(accessToken);
        const payload = decodeJwt(accessToken);
        if (typeof header.alg === 'string') {
          alg = header.alg;
        }
        if (typeof payload.iss === 'string') {
          unverifiedIss = payload.iss;
        }
      } catch (error) {
        const message = (error as Error).message;
        throw this.#addChallenges(new VerifyAccessTokenError(message), mode, scheme);
      }

      if (alg && alg.toUpperCase().startsWith('HS')) {
        throw this.#addChallenges(
          new VerifyAccessTokenError('unsupported algorithm (symmetric algorithms are not supported)'),
          mode,
          scheme
        );
      }

      if (domains !== undefined) {
        if (!unverifiedIss) {
          throw this.#addChallenges(new VerifyAccessTokenError('missing required "iss" claim'), mode, scheme);
        }

        const context: DomainsResolverContext = {
          url: httpUrl,
          headers: options.headers,
          unverifiedIss,
        };

        const allowedDomains = await this.#resolveDomains(domains, context, mode, scheme);
        const matchedDomain = allowedDomains.find((domain) => domain === unverifiedIss);
        if (!matchedDomain) {
          throw this.#addChallenges(
            new VerifyAccessTokenError(
              'unexpected "iss" claim value (issuer is not in the configured domain list)'
            ),
            mode,
            scheme
          );
        }

        const { serverMetadata } = await this.#discoverDomain(matchedDomain);
        const { issuer, jwksUri } = this.#requireDiscoveryMetadata(serverMetadata, mode, scheme);
        issuerForVerify = issuer;
        jwks = this.#getJwksForDomain(jwksUri);
      } else if (defaultDomainUrl !== undefined) {
        const { serverMetadata } = await this.#discoverDomain(defaultDomainUrl);
        const { issuer, jwksUri } = this.#requireDiscoveryMetadata(serverMetadata, mode, scheme);
        issuerForVerify = issuer;
        jwks = this.#getJwksForDomain(jwksUri);
      } else {
        throw new MissingRequiredArgumentError('domain or domains');
      }

      const jwtVerifyOptions: Parameters<typeof jwtVerify>[2] = {
        audience: this.#audience,
        algorithms: options.algorithms ? normalizeAlgorithms(options.algorithms) : this.#algorithms,
        requiredClaims: ['iat', 'exp', ...(options.requiredClaims || [])],
        issuer: issuerForVerify,
      };

      const { payload } = await jwtVerify(accessToken, jwks, jwtVerifyOptions);

      this.#enforceOrganizationPolicy(payload as VerifiedAccessTokenClaims, mode, scheme);

      // Present only when the token is bound to a key (DPoP).
      const cnfJkt = getConfirmationThumbprint(payload);

      const hasProof = typeof dpopProof === 'string';

      // DPoP validation logic
      if (mode !== 'disabled' && scheme === 'bearer' && hasProof && !cnfJkt) {
        throw this.#addChallenges(
          new InvalidRequestError('DPoP proof requires the DPoP authentication scheme, not Bearer'),
          mode,
          scheme
        );
      }

      // Determine if DPoP verification is needed
      const shouldVerifyDpop =
        mode !== 'disabled' && (mode === 'required' || scheme === 'dpop' || hasProof || !!cnfJkt);

      // Enforce DPoP binding when `cnf.jkt`
      if (mode !== 'disabled' && scheme === 'dpop' && !cnfJkt) {
        const err = new VerifyAccessTokenError('JWT Access Token has no jkt confirmation claim');
        err.cause = { code: 'dpop_binding_mismatch' };
        throw this.#addChallenges(err, mode, scheme, { dpopSpecific: true });
      }

      // Enforce scheme when token is DPoP-bound
      if (scheme === 'bearer' && cnfJkt && mode !== 'disabled') {
        throw this.#addChallenges(
          new VerifyAccessTokenError('DPoP-bound token requires the DPoP authentication scheme, not Bearer'),
          mode,
          scheme
        );
      }

      // If DPoP verification is not needed, return the payload early.
      if (!shouldVerifyDpop) {
        return this.#brand(payload, accessToken);
      }

      // Validate DPoP proof presence and related params
      if (!dpopProof) {
        throw this.#addChallenges(new InvalidRequestError(''), mode, scheme, {
          dpopSpecific: true,
          includeError: false,
        });
      }

      // Validate HTTP method and URL presence
      if (typeof httpMethod !== 'string' || !httpMethod) {
        throw this.#addChallenges(
          new InvalidRequestError('HTTP method is required for DPoP validation'),
          mode,
          scheme,
          { dpopSpecific: true }
        );
      }

      // Validate HTTP URL presence
      if (typeof httpUrl !== 'string' || !httpUrl) {
        throw this.#addChallenges(new InvalidRequestError('HTTP URL is required for DPoP validation'), mode, scheme, {
          dpopSpecific: true,
        });
      }

      // Perform DPoP proof verification
      try {
        await verifyDpopProof({
          proof: dpopProof,
          accessToken: options.accessToken,
          method: httpMethod,
          url: httpUrl,
          cnfJkt,
          iatOffset,
          iatLeeway,
          algorithms: ALLOWED_DPOP_ALGORITHMS,
        });
      } catch (err) {
        if (
          err instanceof VerifyAccessTokenError ||
          err instanceof InvalidDpopProofError ||
          err instanceof InvalidRequestError
        ) {
          // Handle DPoP-specific errors with appropriate challenges
          throw this.#addChallenges(err as Error, mode, scheme, { dpopSpecific: true });
        }
        throw err;
      }

      return this.#brand(payload, accessToken);
    } catch (e) {
      if (e instanceof AuthError) {
        throw e;
      }
      const message = e instanceof Error ? e.message : String(e);
      const err = new VerifyAccessTokenError(message);
      throw this.#addChallenges(err, mode, scheme);
    }
  }

  /**
   * Records that this instance produced `payload` by verifying `accessToken`, and returns
   * it typed as verified claims.
   */
  #brand(payload: object, accessToken: string): VerifiedAccessTokenClaims {
    // The copy is taken before the object is handed out, so nothing the caller does to
    // the returned object afterwards can reach it. A shallow copy is enough: every claim
    // the cache key reads is a top-level primitive.
    this.#verifiedClaims.set(payload, {
      accessToken,
      claims: { ...payload } as VerifiedAccessTokenClaims,
    });
    return payload as VerifiedAccessTokenClaims;
  }

  async #resolveDomains(
    domains: string[] | DomainsResolver,
    context: DomainsResolverContext,
    mode: NonNullable<DPoPOptions['mode']>,
    scheme: string
  ): Promise<string[]> {
    if (Array.isArray(domains)) {
      return domains;
    }

    let resolved: string[];
    try {
      resolved = await domains(context);
    } catch {
      throw this.#addChallenges(
        new VerifyAccessTokenError('domain validation failed: domains resolver failed'),
        mode,
        scheme
      );
    }

    if (!Array.isArray(resolved)) {
      throw this.#addChallenges(
        new VerifyAccessTokenError(
          'domain validation failed: domains resolver must return an array of domain strings'
        ),
        mode,
        scheme
      );
    }

    if (resolved.length === 0) {
      throw this.#addChallenges(
        new VerifyAccessTokenError(
          'domain validation failed: domains resolver returned no allowed domains'
        ),
        mode,
        scheme
      );
    }

    const normalized: string[] = [];
    for (const domain of resolved) {
      if (typeof domain !== 'string' || !domain.trim()) {
        throw this.#addChallenges(
          new VerifyAccessTokenError(
            'domain validation failed: domains resolver returned a non-string domain'
          ),
          mode,
          scheme
        );
      }
      try {
        normalized.push(normalizeDomain(domain));
      } catch (error) {
        const message = (error as Error).message;
        throw this.#addChallenges(new VerifyAccessTokenError(message), mode, scheme);
      }
    }

    return Array.from(new Set(normalized));
  }

  #requireDiscoveryMetadata(
    serverMetadata: oauth.AuthorizationServer,
    mode: NonNullable<DPoPOptions['mode']>,
    scheme: string
  ): { issuer: string; jwksUri: string } {
    if (!serverMetadata.jwks_uri) {
      throw this.#addChallenges(
        new VerifyAccessTokenError('missing "jwks_uri" in discovery metadata'),
        mode,
        scheme
      );
    }

    return { issuer: serverMetadata.issuer, jwksUri: serverMetadata.jwks_uri };
  }

  #getJwksForDomain(jwksUri: string) {
    const existing = this.#jwksByUri.get(jwksUri);
    if (existing) {
      return existing;
    }

    const jwksUrl = new URL(jwksUri);
    const jwks = createRemoteJWKSet(jwksUrl, {
      [customFetch]: this.#createJwksFetch(),
    });
    this.#jwksByUri.set(jwksUri, jwks);
    return jwks;
  }

  #createJwksFetch() {
    const baseFetch = this.#options.customFetch ?? fetch;
    return async (input: RequestInfo | URL, init?: RequestInit) => {
      try {
        const response = await baseFetch(input, init);
        if (!response.ok) {
          throw new Error('JWKS request failed');
        }
        return response;
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('JWKS request failed')) {
          throw error;
        }
        throw new Error('JWKS request failed');
      }
    };
  }

  #enforceOrganizationPolicy(
    claims: VerifiedAccessTokenClaims,
    mode: NonNullable<DPoPOptions['mode']>,
    scheme: string
  ): void {
    if (this.#organizationPolicy !== 'required') {
      return;
    }

    const orgId = claims['org_id'];
    if (typeof orgId !== 'string' || orgId.trim() === '') {
      throw this.#addChallenges(new MissingOrganizationError(), mode, scheme);
    }

    if (this.#organizationAllowlist !== undefined && !this.#organizationAllowlist.has(orgId)) {
      throw this.#addChallenges(new OrganizationNotAllowedError(), mode, scheme);
    }
  }

  #addChallenges<T extends Error & { code?: string; headers?: Record<string, string | string[]> }>(
    err: T,
    mode: NonNullable<DPoPOptions['mode']>,
    scheme: string,
    params?: { dpopSpecific?: boolean; includeError?: boolean; target?: 'bearer' | 'dpop' }
  ) {
    const authErr = err;
    if (!authErr.headers) {
      const includeError = params?.includeError ?? true;
      const target = params?.target ?? (params?.dpopSpecific === true ? 'dpop' : scheme === 'dpop' ? 'dpop' : 'bearer');
      let challengeCode = authErr.code;
      if (authErr instanceof VerifyAccessTokenError) {
        challengeCode = 'invalid_token';
      } else if (authErr instanceof InvalidRequestError) {
        challengeCode = 'invalid_request';
      } else if (authErr instanceof InvalidDpopProofError) {
        challengeCode = 'invalid_dpop_proof';
      }
      const challengeParams =
        includeError && target === 'dpop'
          ? { dpopError: challengeCode, dpopErrorDescription: authErr.message }
          : includeError && target === 'bearer'
          ? { error: challengeCode, errorDescription: authErr.message }
          : {};
      authErr.headers = buildChallenges(mode, ALLOWED_DPOP_ALGORITHMS, challengeParams);
    }
    return authErr;
  }

  /**
   * Verifies the Poppy Session of a request to a route that needs one. With `requireSession: true`, the
   * `Poppy-Session` header is checked even when the `verifySession` option of `poppy` is off, a request that ends with
   * no verified Session throws an {@link InvalidSessionError} with the reason `missing_session`, and so `poppy` is
   * always set in the result.
   *
   * The compiler chooses this signature when `requireSession` has the type `true`, as the literal `true` in the object
   * that you pass to the call does. A `requireSession` of type `boolean` chooses the general signature, where `poppy`
   * is optional. The checks, their order and the errors are described with that one: see
   * {@link ApiClient.verifyPoppyRequest}.
   *
   * @param options - The request to verify, with `requireSession: true`.
   * @returns The verified Session as `poppy`, and the claims of the access token as `claims` when the request carried
   * one.
   * @throws {InvalidSessionError} A check of the Session failed (the `reason` says which), or the request has no
   * Session (`missing_session`). Status 400.
   * @throws {SessionEndedError} The store says the Session has ended. Status 400.
   * @throws {PoppyUnavailableError} The host of the agent can't be reached. Status 503.
   * @throws {VerifyAccessTokenError} The access token failed verification. Status 401, with challenges.
   * @throws {InvalidDpopProofError} The DPoP proof failed verification. Status 400, with challenges.
   * @throws {InvalidRequestError} The `Authorization` header is not one credential, or the request is refused as
   * `verifyAccessToken` refuses it, or the URL is used and has no path. Status 400.
   * @throws {InvalidConfigurationError} A mistake of your setup, so answer 500: `headers` is not a plain object,
   * the URL is used while there is no public origin and `url` is not an absolute URL, or a `domains` function returned
   * something that is not a list of domains.
   *
   * These are described with {@link ApiClient.verifyPoppyRequest}. {@link toHttpErrorResponse} turns the first six into
   * the response that the specification asks for.
   * @beta
   * @category Poppy
   */
  verifyPoppyRequest(
    options: VerifyPoppyRequestOptions & { requireSession: true }
  ): Promise<VerifiedPoppyRequest & { poppy: PoppySession }>;
  /**
   * Verifies the Poppy Session of a request: the signed `Poppy-Session` header that a Personal Agent sends with its
   * requests (section 5.2 of the Poppy 0.3 specification), and the access token next to it, if there is one. It throws
   * when a check fails. Otherwise it returns the verified Session as `poppy` and the claims of the verified access
   * token as `claims`, and leaves out the one that the request does not have.
   *
   * A request with no credentials is not an error. Unless it sets `requireSession`, the result is `{}`, so a route that
   * needs a Session or an account must check `poppy` or `claims` itself.
   *
   * The header is checked when the `verifySession` option of `poppy` is on, and for every request that sets
   * `requireSession`. Otherwise it is ignored entirely: it is not parsed, nothing is fetched for it, and nothing of it
   * is returned. A request without a Session has no `poppy`, or the call throws `missing_session` when `requireSession`
   * is set. The method works without the `poppy` option as well, with every setting at its default. Then only a
   * request that sets `requireSession` has its header checked. For a route that needs a Session, pass
   * `requireSession: true` as a literal: `poppy` is then typed as always set in the result.
   *
   * An access token comes from the `Authorization` header, and a DPoP proof from the `DPoP` header. The token is
   * verified by {@link ApiClient.verifyAccessToken}, with its rules and the DPoP mode of the client, whether the
   * Session checks are on or not, and its errors reach you as they are, with their challenges. That is the only call to
   * Auth0, so a request with no access token makes none. The other network requests are the ones to the agent, for its
   * client metadata and its keys: over HTTPS, without redirects, within a time limit and a size limit, and cached (see
   * {@link PoppyAgentMetadataOptions}).
   *
   * For a request with a `Poppy-Session` header to check, the checks run in this order (section 5.3 of the
   * specification), and the first one that fails throws:
   * 1. The header has exactly one value, and it is a Session JWT of the right shape: compact form, `typ`
   *    `poppy-session+jwt`, `alg` `ES256`, a `kid` and a delegation in `poppy_dlg`, and the claims `iss`, `aud`,
   *    `sid`, `sub`, `htm`, `htu`, `iat` and `jti`.
   * 2. The agent in `iss` is one of the registered agents, when `agents` (or the `agents` of `config`) is set. Nothing
   *    is fetched until this and the check before it have passed.
   * 3. The delegation is verified with a key of the agent, and then the signature of the Session JWT is verified with
   *    the key that the delegation vouches for. The client metadata and the key set of the agent are fetched here, and
   *    cached.
   * 4. The claims match the request:
   *    - `aud` is the issuer of your Auth0 domain, compared character by character: `https://example.auth0.com/` for
   *      the domain `example.auth0.com`. With `domains`, it is the issuer of one of them. When `domains` is a
   *      function, it is called with the `url` you passed, as it is, and the `headers` of the request, and with the
   *      `aud` of the Session JWT as `unverifiedIss`. The issuers it returns are the ones allowed, and an empty list
   *      refuses every Session JWT with `claim_mismatch`.
   *    - `htm` is the method of the request, in any letter case.
   *    - `htu` is the URL of the request without its query and fragment. With a public origin (`publicOrigin`) it is
   *      that origin and the path of `url`, so a server behind a proxy matches the URL that the agent signed, and `url`
   *      may also be a path. Without a public origin it is `url` itself, which must then be an absolute URL.
   *    - `iat` is within `iatWindow` seconds of now, in both directions.
   * 5. The `ath` of the Session JWT: without an access token it must be absent. With one, it must be the hash of the
   *    token (RFC 9449, section 4.2). It is checked before the token is verified, so a Session JWT that is wrong costs
   *    no request to Auth0.
   * 6. The access token is verified, as `verifyAccessToken` does for the scheme of the `Authorization` header (Bearer
   *    or DPoP). A DPoP proof is checked against the `htu` of step 4, so behind a public origin it names the public
   *    URL. A `domains` function is called again for the token, as `verifyAccessToken` calls it, with the `iss` of the
   *    token as `unverifiedIss`. Its `url` is the one that `htu` is compared with here: the public origin and the path
   *    when there is a public origin, and otherwise `url` as it is.
   * 7. The access token was issued to the agent of the Session: its `client_id` claim, else its `azp` claim, is the
   *    `iss`. A token with neither claim is refused.
   * 8. With a `sessionStore`, a known Session has the User ID and the Agent ID of its record, and has not ended, and a
   *    new Session is saved (see {@link PoppySessionStore}).
   *
   * An `Authorization` header that is not one credential (two or more values, or a comma in its value) is refused with
   * an {@link InvalidRequestError} and the challenges of `verifyAccessToken`. With a Session header to check it falls
   * after step 4 and before step 5, and a Session JWT that failed an earlier step is refused first.
   *
   * A request with an access token and no `Poppy-Session` header to check goes through these checks instead, and a
   * request with neither has an empty result. The `Authorization` header is read first: a header that is not one
   * credential is refused before the URL is looked at and before the token is verified. The URL of the request is
   * worked out only when the token step uses it, for a DPoP proof or a `domains` function, so a Bearer token with no
   * such function may come with a path as `url`, and needs no public origin.
   * 1. The access token is verified, as in step 6.
   * 2. With the Session checks on (`verifySession`, or `requireSession` on the request), a token issued to a registered
   *    agent is refused with `missing_session`, because a registered agent sends the header with every request. The
   *    agent is the `client_id` claim of the token, else its `azp` claim, and the rule applies whatever the `act` claim
   *    of the token holds.
   * 3. A token whose `act` claim has a `poppy_sid` holds a Session. These are the beta claims that Auth0 issues to a
   *    web app: `act.sub` is the URL of the agent, `act.poppy_sid` the Session ID, `act.poppy_user_id` the User ID and
   *    `act.poppy_agent_id` the Agent ID, which may be left out. They are read whether or not the Session checks are
   *    on. They must be well formed, or the call throws `malformed_session`, and a token without a `poppy_sid` holds no
   *    Session. The `agents` option does not filter this Session (`source: 'token'`): if you need that, check
   *    `poppy.agent.cimdUrl` yourself.
   * 4. With a `sessionStore`, the Session of the token is checked as in step 8.
   *
   * Answer a failed check with {@link toHttpErrorResponse}, which gives the status, the headers and the body that the
   * specification asks for.
   *
   * @param options - The request to verify: its method, URL and headers, and whether it needs a Session.
   * @returns `{ poppy, claims }`, with each one left out when the request has none of it. `poppy` is the verified
   * Session, and `poppy.source` says where it came from: `'header'` for the `Poppy-Session` header and `'token'` for
   * the `act` claim of the access token. `poppy.state` is `'signed_in'` when an access token was verified with the
   * Session, so a Session from the header alone is `'signed_out'`. A Session from the `act` claim of a token is
   * `'signed_in'`, unless the token is the token of a guest (an anonymous user, marked by `sub_profile` or by a `sub`
   * that starts with `anon_poppy@`): that Session is `'signed_out'`, and `claims.sub` is not an account. `claims` are
   * the claims of the verified access token, and they are set whenever the request carried one. Key the state of the
   * Session, such as a cart, by `poppy.key`, which is unique for each agent and Session ID. `poppy.sessionId` alone is
   * not.
   * @throws {InvalidSessionError} When a check of the Session fails (the `reason` says which one, such as
   * `ath_mismatch` or `token_client_mismatch` for the access token), when `requireSession` is set and the request has
   * no Session (`missing_session`), or when the access token of a registered agent comes without the header
   * (`missing_session`).
   * @throws {SessionEndedError} When the store says the Session has ended.
   * @throws {PoppyUnavailableError} When the host of the agent can't be reached, answers 429 or 5xx, or is too slow.
   * It is not a verdict on the Session: answer 503, and the agent retries later.
   * @throws {VerifyAccessTokenError} When the access token fails verification. It is the error of `verifyAccessToken`
   * as it is, with status 401 and the `WWW-Authenticate` challenges in `headers`.
   * @throws {InvalidDpopProofError} When the DPoP proof fails verification, as `verifyAccessToken` gives it: status 400
   * and the challenges in `headers`.
   * @throws {InvalidRequestError} Status 400 and the challenges in `headers`, when the `Authorization` header is not
   * one credential, or when `verifyAccessToken` refuses the request, as it does for a scheme it does not accept or a
   * DPoP request without a proof. Also, with no challenges, when the URL is used (a `Poppy-Session` header to check, a
   * DPoP proof or a `domains` function), there is a public origin, and `url` is neither a path nor an absolute URL with
   * a path.
   * @throws {InvalidConfigurationError} When `headers` is not a plain object (see {@link VerifyPoppyRequestOptions}),
   * when the URL is used and there is no public origin and `url` is not an absolute URL, or when a `domains` function
   * returns something that is not a list of domains. An empty list is a list: it refuses the Session JWT. These are
   * mistakes of the setup: answer 500. An error that your `domains` function or your store throws reaches you as it is.
   * @see {@link https://personalagentprotocol.org/docs/0.3/spec Poppy 0.3 specification}
   * @beta
   * @category Poppy
   *
   * @example
   * ```typescript
   * import { ApiClient, toHttpErrorResponse } from '@auth0/auth0-api-js';
   *
   * const apiClient = new ApiClient({
   *   domain: 'example.auth0.com',
   *   audience: 'https://api.example.com',
   *   poppy: { verifySession: true },
   * });
   *
   * // A handler for a Fetch API `Request`. It returns what to answer, for your framework to send.
   * export async function handle(request: Request) {
   *   try {
   *     const { poppy } = await apiClient.verifyPoppyRequest({
   *       method: request.method,
   *       url: request.url,
   *       headers: Object.fromEntries(request.headers),
   *     });
   *
   *     // Key the state of this Session, such as its cart, by `poppy.key`. Never use `poppy.sessionId` alone.
   *     return { status: 200, body: { session: poppy?.key ?? null } };
   *   } catch (error) {
   *     // The status, the headers (such as `retry-after`) and the JSON body that the specification asks for.
   *     const failure = toHttpErrorResponse(error);
   *     if (!failure) {
   *       throw error; // Not a failure of the request: let your framework answer 500.
   *     }
   *     return failure;
   *   }
   * }
   * ```
   */
  verifyPoppyRequest(options: VerifyPoppyRequestOptions): Promise<VerifiedPoppyRequest>;
  async verifyPoppyRequest(options: VerifyPoppyRequestOptions): Promise<VerifiedPoppyRequest> {
    return runPoppyPipeline(this.#poppyPipeline(), options);
  }

  /**
   * What `verifyPoppyRequest` runs on: the resolved `poppy` options, the parts that keep state (the fetcher and the
   * delegation verifier, with their caches) and the functions that reach back into this client. It is built once, on
   * first use, and the same object serves every request. The functions look up `verifyAccessToken` and the DPoP mode
   * when they are called, so a method that is replaced later, as a test does, or an option that is read at call time,
   * is seen.
   */
  #poppyPipeline(): PoppyPipeline {
    if (this.#poppyPipelineCache === undefined) {
      const options = this.#resolvePoppy();
      const fetcher = new AgentMetadataFetcher(options.agentMetadata);
      const delegations = new DelegationVerifier(fetcher, {
        iatWindowSeconds: options.iatWindowSeconds,
        cacheMaxEntries: DEFAULT_DELEGATION_CACHE_MAX_ENTRIES,
        // A delegation is kept as long as the keys of its agent, so removing a key from a key set revokes its delegations.
        ttlMs: options.agentMetadata.ttlMs,
      });
      this.#poppyPipelineCache = {
        options,
        fetcher,
        delegations,
        hasDomainsResolver: typeof this.#domains === 'function',
        verifyAccessToken: (tokenOptions) => this.verifyAccessToken(tokenOptions),
        audiences: (context) => this.#poppyAudiences(context),
        // The scheme is `bearer`, which `verifyAccessToken` also assumes when a request names none.
        addChallenges: (error) => this.#addChallenges(error, this.#options.dpop?.mode ?? 'allowed', 'bearer'),
      };
    }
    return this.#poppyPipelineCache;
  }

  /**
   * The values the `aud` of a Session JWT may have for one request: the issuer of `domain`, or the issuers of
   * `domains`, which are compared with `aud` character by character. A `domains` function gets the `aud` as
   * `unverifiedIss`, and its own errors reach the caller unchanged.
   */
  async #poppyAudiences(context: {
    url: string;
    headers: VerifyPoppyRequestOptions['headers'];
    unverifiedAud: string;
  }): Promise<readonly string[]> {
    const domains = this.#domains;
    if (Array.isArray(domains)) {
      return domains;
    }
    if (typeof domains === 'function') {
      const resolved = await domains({
        url: context.url,
        headers: context.headers,
        unverifiedIss: context.unverifiedAud,
      });
      return normalizeResolvedDomains(resolved);
    }

    // The constructor throws without `domain` or `domains`, and `domains` is not set here, so `domain` is.
    if (this.#defaultDomainUrl === undefined) {
      throw new MissingRequiredArgumentError('domain or domains');
    }
    return [this.#defaultDomainUrl];
  }

  /**
   * Retrieves an access token for a connection.
   *
   * @param options - Options for retrieving an access token for a connection.
   *
   * @throws {TokenForConnectionError} If there was an issue requesting the access token.
   *
   * @returns The Connection Token Set, containing the access token for the connection, as well as additional information.
   * @category Token Exchange
   */
  public async getAccessTokenForConnection(options: AccessTokenForConnectionOptions): Promise<ConnectionTokenSet> {
    if (!this.#authClient) {
      throw new TokenForConnectionError('Client credentials are required to use getAccessTokenForConnection');
    }

    const tokenEndpointResponse = await this.#authClient.getTokenForConnection({
      connection: options.connection,
      loginHint: options.loginHint,
      accessToken: options.accessToken,
    });

    return {
      accessToken: tokenEndpointResponse.accessToken,
      scope: tokenEndpointResponse.scope,
      expiresAt: tokenEndpointResponse.expiresAt,
      connection: options.connection,
      loginHint: options.loginHint,
    };
  }

  /**
   * Exchanges a token via a Custom Token Exchange Profile for a different API audience while preserving user identity (RFC 8693).
   *
   * This method supports **Custom Token Exchange** for custom token types via a configured Token Exchange Profile.
   *
   * For **Access Token Exchange with Token Vault** (external provider's access tokens), use {@link getAccessTokenForConnection} instead.
   *
   * **Note**: This method requires a confidential client (client credentials must be configured).
   * While Custom Token Exchange Early Access technically permits public clients, this implementation
   * currently requires client authentication. Public client support may be added in a future release.
   *
   * @param subjectToken - The raw token to be exchanged (without "Bearer " prefix)
   * @param options - Configuration for the token exchange
   *
   * @returns A promise that resolves with the {@link TokenExchangeProfileResult}
   *
   * @throws {TokenExchangeError} When client credentials are not configured or exchange fails
   *
   * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Custom Token Exchange Documentation}
   * @category Token Exchange
   *
   * @example
   * ```typescript
   * // Exchange custom token (organization is optional)
   * const result = await apiClient.getTokenByExchangeProfile(
   *   userToken,
   *   {
   *     subjectTokenType: 'urn:example:custom-token',
   *     audience: 'https://api.backend.com',
   *     organization: 'org_abc123', // Optional - Organization ID or name
   *     scope: 'read:data write:data',
   *   }
   * );
   * // When organization is provided, the access token will include the organization ID in its payload
   * ```
   */
  public async getTokenByExchangeProfile(
    subjectToken: string,
    options: ExchangeProfileOptions
  ): Promise<TokenExchangeProfileResult> {
    // Matches the shipped behavior: an empty `scope` is left out. The on-behalf-of path
    // uses #exchangeByProfile directly because it has to tell empty from absent.
    const { scope, ...rest } = await this.#exchangeByProfile(subjectToken, options);

    return { ...rest, ...(scope && { scope }) };
  }

  async #exchangeByProfile(
    subjectToken: string,
    options: ExchangeProfileOptions
  ): Promise<TokenExchangeProfileResult> {
    if (!this.#authClient) {
      throw new MissingClientAuthError();
    }

    const response = await this.#authClient.exchangeToken({
      subjectTokenType: options.subjectTokenType,
      subjectToken,
      audience: options.audience,
      scope: options.scope,
      requestedTokenType: options.requestedTokenType,
      organization: options.organization,
    });

    return {
      accessToken: response.accessToken,
      expiresAt: response.expiresAt,
      // An empty `scope` has to stay distinct from an absent one. Absent means the grant
      // matched the request (RFC 6749 section 5.1); empty means nothing was granted.
      // Collapsing the two would report a request's own scopes back as if they had been
      // granted.
      ...(response.scope !== undefined ? { scope: response.scope } : {}),
      ...(response.idToken && { idToken: response.idToken }),
      ...(response.refreshToken && { refreshToken: response.refreshToken }),
      ...(response.tokenType && { tokenType: response.tokenType }),
      ...(response.issuedTokenType && { issuedTokenType: response.issuedTokenType }),
    };
  }

  /**
   * Exchanges an Auth0 access token for another Auth0 access token targeting a downstream API
   * while acting on behalf of the same end user (OBO).
   *
   * This is a convenience wrapper around {@link getTokenByExchangeProfile} that fixes the
   * RFC 8693 token types for Auth0 access-token-to-access-token exchange.
   *
   * **Note**: This method requires a confidential client (client credentials must be configured).
   * The SDK forwards the incoming access token as the `subject_token` and applies no
   * DPoP-specific handling during the exchange itself.
   *
   * ## Caching
   *
   * Pass `context.store` to cache the exchanged token. The token is cached under the scopes
   * the exchange actually **granted**, and those scopes are recorded alongside it, so a later
   * call asking for that narrower set is served from cache. `scopeMatching` on
   * {@link ApiClientOptions} selects exact or covering matching; see {@link ScopeMatching}.
   *
   * In `'strict'` mode a repeat request hits only when its requested scopes equal the scopes
   * the earlier exchange was granted. A response without `scope` means the grant matched the
   * request, so such a request hits. When the grant was narrowed or widened, the entry sits
   * under the granted set and the same request misses and re-exchanges every time. In
   * `'non_strict'` mode a request is also served from any cached token whose granted scopes
   * cover it, which needs an {@link IndexedTokenStore}.
   *
   * A store failure never fails this call. A read that throws, a malformed entry, an
   * entry close to expiry and a failure to derive the cache key on read are all treated as
   * a cache miss, and a write that throws still
   * returns the freshly exchanged token. A cached entry is shape-validated but not
   * integrity-checked, so a store shared with other software is trusted to return exactly
   * what was written to it.
   *
   * A token whose claims cannot be keyed unambiguously is never cached. If `iss`,
   * `client_id`, `azp`, `sub`, `org_id`, `sid` or `jti` is present with a value that is not
   * a string, the call proceeds as an ordinary uncached exchange. A conforming token never
   * does this.
   *
   * This method does **not** reject a result that came back with fewer scopes than were
   * requested. It caches it under what was granted and returns it, with `scope` set to
   * exactly what the authorization server sent. Deciding whether a narrowed grant is
   * acceptable belongs to the caller, which has the request context needed to turn it into
   * the right response. Use `grantedScopes` on the result to make that decision: it is
   * always present, on a fresh exchange and on a cache hit alike. `scope` is not enough,
   * because an authorization server that omits it means the scopes were granted as
   * requested (RFC 6749 section 5.1), while an empty `scope` means nothing was granted.
   *
   * ## Verifying the subject token
   *
   * Caching needs the subject token's claims to derive a cache key, so the token is
   * verified when, and only when, a store is supplied. Without a store the token is
   * forwarded untouched, exactly as it was before caching existed.
   *
   * That internal verification runs as a bearer token with no request context, so it cannot
   * satisfy `dpop.mode: 'required'`, accept a DPoP-bound token, or give a `domains` resolver
   * a URL or headers. Pass `context.verified` in those cases: verify once at your ingress,
   * where the scheme, the proof and the headers are available, and hand the result in.
   *
   * Supplied claims are only trusted when all of the following hold, and the call is
   * rejected otherwise. Claims this instance never produced are an integration bug and throw
   * `InvalidConfigurationError`; claims that belong to a different token or have expired
   * throw `VerifyAccessTokenError` with the same challenges as `verifyAccessToken`:
   * - `verified.claims` is the very object that `verifyAccessToken` on this same
   *   `ApiClient` instance returned. The check is on object identity, so the claims cannot
   *   be serialized, cloned, spread into a new object or sent across a worker boundary, and
   *   claims verified by a different `ApiClient` instance are refused.
   * - `verified.accessToken` equals `accessToken`, and is the token those claims were
   *   verified from.
   * - The claims have not expired: `exp` must be later than the current time plus a few
   *   seconds of leeway.
   *
   * The cache key is derived from a copy of the claims taken when `verifyAccessToken`
   * returned them, not from the object you pass in. Adding to or changing the claims object
   * after verification, for example setting `sub` to another subject, has no effect on the
   * cache key or on which cached token is read or written.
   *
   * When an `organizationPolicy` is configured, it is also applied to that trusted copy of
   * the claims before the cache is read, with the same checks and errors as
   * `verifyAccessToken`.
   *
   * @param accessToken - The Auth0 access token to exchange (without "Bearer " prefix)
   * @param options - Configuration for the downstream audience and optional scope
   * @param context - Optional per-call cache and pre-verified subject token
   *
   * @returns A promise that resolves with the {@link OnBehalfOfTokenResult}, including the
   * scopes the exchange actually granted in `grantedScopes`
   *
   * @throws {MissingClientAuthError} When client credentials are not configured, meaning
   * neither a client secret nor a client assertion signing key. This is checked first,
   * before any verification or cache access, even when a client id is set.
   * @throws {TokenExchangeError} When the exchange fails
   * @throws {VerifyAccessTokenError} When a store is supplied and the subject token does not verify
   * @throws {MissingOrganizationError} When a store is supplied, `organizationPolicy` is
   * `'required'` and the subject token carries no organization
   * @throws {OrganizationNotAllowedError} When a store is supplied and the subject token's
   * organization is not in the configured `organizationId` allowlist
   * @throws {VerifyAccessTokenError} When `context.verified` does not match `accessToken`,
   * or when its claims have expired
   * @throws {InvalidConfigurationError} When the claims in `context.verified` were not
   * returned by `verifyAccessToken` on this same `ApiClient` instance (object identity is
   * required, so a clone or deserialized copy is rejected)
   * @throws {InvalidConfigurationError} When `scopeMatching` is `'non_strict'` without an
   * {@link IndexedTokenStore}
   * @category Token Exchange
   *
   * @example
   * ```typescript
   * const result = await apiClient.getTokenOnBehalfOf(incomingAccessToken, {
   *   audience: 'https://api.backend.com',
   *   scope: 'read:data write:data',
   * });
   * ```
   *
   * @example Cached, with the token verified at ingress
   * ```typescript
   * const claims = await apiClient.verifyAccessToken({
   *   accessToken: incomingAccessToken,
   *   scheme: 'dpop',
   *   dpopProof: request.headers.get('dpop') ?? undefined,
   *   httpMethod: request.method,
   *   httpUrl: request.url,
   * });
   *
   * const result = await apiClient.getTokenOnBehalfOf(
   *   incomingAccessToken,
   *   { audience: 'https://api.backend.com', scope: 'read:data' },
   *   { store, verified: { accessToken: incomingAccessToken, claims } }
   * );
   * ```
   */
  public async getTokenOnBehalfOf(
    accessToken: string,
    options: OnBehalfOfTokenOptions,
    context?: OnBehalfOfTokenContext
  ): Promise<OnBehalfOfTokenResult> {
    // Snapshot everything the cache key and the exchange depend on, once. The caller's
    // options object may be shared and mutated while this call is awaiting the store, and
    // reading it again afterwards could exchange for one audience and cache the result
    // under another.
    const requestedAudience = options.audience;
    const requestedScope = options.scope;
    const store = context?.store;
    const scopeMatching = this.#scopeMatching;

    // Fail before any verification or cache access, so a client without credentials is
    // not served from a shared cache that an authenticated client populated. Having a
    // client id is not enough: without a secret or an assertion signing key the exchange
    // could never succeed.
    if (!this.#authClient || !this.#hasClientAuth) {
      throw new MissingClientAuthError();
    }

    // A supplied pre-verified token is bound to the token being exchanged whether or not
    // the cache ends up using it, so a mismatch fails loudly instead of being ignored on
    // the paths that happen not to need the claims.
    if (context?.verified !== undefined && context.verified.accessToken !== accessToken) {
      const mode = this.#options.dpop?.mode ?? 'allowed';
      const supplied = context.verified.claims as object | null | undefined;
      const record = typeof supplied === 'object' && supplied !== null ? this.#verifiedClaims.get(supplied) : undefined;
      throw this.#addChallenges(
        new VerifyAccessTokenError(PRE_VERIFIED_REJECTION_MESSAGE),
        mode,
        record === undefined ? 'bearer' : this.#schemeFor(record.claims, mode)
      );
    }

    // Covering matching has to search several entries per subject, which needs an index.
    // Checked before anything else so a store that cannot support the configured mode is
    // reported as the configuration error it is, rather than silently matching exactly.
    if (scopeMatching === 'non_strict' && (store === undefined || !isIndexedTokenStore(store))) {
      throw new InvalidConfigurationError(
        'Invalid scope matching configuration: "non_strict" requires an IndexedTokenStore to be passed as the token store'
      );
    }

    const cache =
      store === undefined
        ? undefined
        : await this.#oboCacheAccess(store, scopeMatching, accessToken, requestedAudience, context);

    const requestedScopes = normalizeScopes(requestedScope);

    if (cache !== undefined) {
      const cached = await readOboCachedToken(cache, requestedScopes);

      if (cached !== undefined) {
        return toOnBehalfOfTokenResult(cached, cached.grantedScopes);
      }
    }

    const result = await this.#exchangeByProfile(accessToken, {
      subjectTokenType: OBO_ACCESS_TOKEN_TYPE,
      requestedTokenType: OBO_ACCESS_TOKEN_TYPE,
      audience: requestedAudience,
      scope: requestedScope,
    });

    // An absent `scope` means the grant matched the request (RFC 6749 section 5.1), so
    // the requested set is what was granted. An empty `scope` means nothing was granted
    // and is recorded as such.
    const grantedScopes = result.scope !== undefined ? normalizeScopes(result.scope) : requestedScopes;

    if (cache !== undefined) {
      await writeOboCachedToken(cache, { ...toOnBehalfOfTokenResult(result, grantedScopes), grantedScopes });
    }

    return toOnBehalfOfTokenResult(result, grantedScopes);
  }

  /**
   * Acquires an access token using the OAuth 2.0 client credentials grant.
   *
   * Requires the client to be constructed with `clientId` and at least one of
   * `clientSecret` or `clientAssertionSigningKey`; throws `MissingClientAuthError`
   * otherwise.
   *
   * The `audience` defaults to the audience configured at construction time.
   * Pass an explicit `audience` to override for a specific downstream API.
   *
   * Every call performs a token request. This method holds no cache, so a
   * caller that needs one has to add it.
   *
   * `scope` is forwarded to the token endpoint, which needs
   * `@auth0/auth0-auth-js` 1.18.0 or later, so this package requires that
   * version as a minimum. Whitespace in `scope` is normalized to single spaces.
   * A `null` or `undefined` scope is omitted from the request. A blank or
   * non-string scope throws `InvalidScopeError` before any request is made,
   * because Auth0 would treat it as omitted and issue the full grant.
   *
   * The requested `scope` does not narrow the token Auth0 issues. Read the
   * granted `scope` on the result to see what the token actually carries.
   *
   * @param options - Options for the client credentials grant.
   * @param options.audience - Target API audience. Defaults to `this.#options.audience`.
   * @param options.scope - Space-separated OAuth 2.0 scopes. Omit (or pass `null`) to send no scope parameter.
   *
   * @returns Promise resolving to a `TokenSet` with `accessToken` and `expiresAt`,
   *   plus the granted `scope` and `tokenType` when they are reported. `scope`
   *   is returned exactly as the server sent it. An absent `scope` means the
   *   scopes were granted as requested (RFC 6749 section 5.1), and an empty
   *   string means nothing was granted. The two are kept apart, so test for
   *   `undefined` rather than for falsiness.
   *
   * @throws {MissingClientAuthError} When no client credentials are configured.
   * @throws {InvalidScopeError} When `scope` is blank or not a string.
   * @throws {TokenByClientCredentialsError} When Auth0 returns an error response.
   */
  public async getClientCredentialsToken(options: { audience?: string; scope?: string | null }): Promise<TokenSet> {
    if (!this.#authClient) {
      throw new MissingClientAuthError();
    }

    const audience = options.audience ?? this.#options.audience;

    const response = await this.#authClient.getTokenByClientCredentials({
      audience,
      ...(options.scope !== undefined && { scope: options.scope }),
    });

    // Surface the granted scope and token type rather than dropping them, so a
    // caller can detect that Auth0 granted less than was asked for.
    return {
      accessToken: response.accessToken,
      expiresAt: response.expiresAt,
      ...(response.scope !== undefined && { scope: response.scope }),
      ...(response.tokenType !== undefined && { tokenType: response.tokenType }),
    };
  }

  /**
   * Resolves the claims the cache key is derived from, then assembles everything the
   * cache needs. Returns `undefined` when the token cannot be keyed unambiguously, in
   * which case the caller exchanges without a cache.
   *
   * A supplied pre-verified token is trusted only if this instance produced its claims,
   * they belong to the token being exchanged, and they have not expired.
   */
  async #oboCacheAccess(
    store: TokenStore,
    scopeMatching: ScopeMatching,
    accessToken: string,
    requestedAudience: string,
    context: OnBehalfOfTokenContext | undefined
  ): Promise<OboCacheAccess | undefined> {
    let claims: VerifiedAccessTokenClaims;

    if (context?.verified !== undefined) {
      // On this path the claims come from the copy recorded when this instance verified
      // the token, never from the object the caller passed. The caller's object is only
      // used to look that record up. Mutating it, before or after this call, therefore
      // cannot change the cache key: the key is derived from what was actually verified.
      const mode: NonNullable<DPoPOptions['mode']> = this.#options.dpop?.mode ?? 'allowed';
      claims = this.#assertPreVerifiedTrusted(context.verified, accessToken, mode);

      // Verification is skipped on this path, so the organization policy is applied to
      // the trusted copy here, with the same checks and challenges verifyAccessToken
      // uses. It runs before the key is derived, so a rejected token never reaches the store.
      const scheme = this.#schemeFor(claims, mode);
      this.#enforceOrganizationPolicy(claims, mode, scheme);
    } else {
      // Take a copy so a later change to the returned object cannot make the key used for
      // the write differ from the one used for the read.
      claims = { ...(await this.verifyAccessToken({ accessToken })) };
    }

    // A conforming token never trips this. The key encoding cannot distinguish a claim
    // that is present with a non-string value from one that is absent, so keying such a
    // token could make two different subjects share an entry. Skipping the cache is safer.
    if (hasUnkeyableClaims(claims)) {
      return undefined;
    }

    const identity: OboCacheKeyIdentity = {
      exchangeTenant: this.#defaultDomainUrl,
      exchangeClientId: this.#clientId,
      exchangeAudience: this.#audience,
      verified: { accessToken, claims },
      requestedAudience,
    };

    return { store, scopeMatching, identity };
  }

  /**
   * The challenge scheme for already-verified claims. verifyAccessToken rejects a token
   * bound to a key (cnf.jkt) when it is presented as a bearer token and DPoP is not
   * disabled, so a bound token that verified successfully was presented as DPoP and the
   * challenge has to name that scheme.
   */
  #schemeFor(claims: object, mode: NonNullable<DPoPOptions['mode']>): 'dpop' | 'bearer' {
    return mode !== 'disabled' && getConfirmationThumbprint(claims) ? 'dpop' : 'bearer';
  }

  /**
   * Rejects a caller-supplied pre-verified token unless this instance produced its claims
   * from the same token string and the claims are still unexpired. The caller has
   * already checked that the token string equals the one being exchanged.
   *
   * Returns the copy of the claims recorded at verification time. Callers must use that
   * copy and never the supplied object.
   */
  #assertPreVerifiedTrusted(
    verified: VerifiedToken,
    accessToken: string,
    mode: NonNullable<DPoPOptions['mode']>
  ): VerifiedAccessTokenClaims {
    const supplied = verified.claims as object | null | undefined;
    const record = typeof supplied === 'object' && supplied !== null ? this.#verifiedClaims.get(supplied) : undefined;

    // Claims this instance never produced (forged, cloned, deserialized, or verified by
    // another instance) are a programming error in the integration, not a problem with the
    // caller's token, so this stays a configuration error and surfaces as a server fault.
    if (record === undefined) {
      throw new InvalidConfigurationError(
        'The "verified" context must hold the claims object returned by verifyAccessToken on this same ApiClient instance.'
      );
    }

    const claims = record.claims;

    // From here on the claims are genuine, so every failure is about the token itself and
    // is reported as an invalid token with the same challenges verifyAccessToken sends.
    if (record.accessToken !== verified.accessToken || verified.accessToken !== accessToken) {
      throw this.#addChallenges(
        new VerifyAccessTokenError(PRE_VERIFIED_REJECTION_MESSAGE),
        mode,
        this.#schemeFor(claims, mode)
      );
    }

    const exp = (claims as { exp?: unknown }).exp;
    const nowSeconds = Math.floor(Date.now() / 1000);

    if (typeof exp !== 'number' || !Number.isFinite(exp) || exp <= nowSeconds + TOKEN_EXPIRY_LEEWAY_SECONDS) {
      throw this.#addChallenges(
        new VerifyAccessTokenError(PRE_VERIFIED_REJECTION_MESSAGE),
        mode,
        this.#schemeFor(claims, mode)
      );
    }

    return claims;
  }
}

/**
 * Generic on purpose: it becomes the `error_description` of the challenge, so it must
 * not say which check a rejected pre-verified token failed.
 */
const PRE_VERIFIED_REJECTION_MESSAGE = 'Invalid token';

// Fixed texts for a result of a `domains` function that cannot be a list of issuers: nothing it returned is in them.
const POPPY_DOMAINS_NOT_ARRAY_MESSAGE =
  'Invalid poppy configuration: the "domains" function must return an array of domain strings';
const POPPY_DOMAINS_NOT_STRING_MESSAGE =
  'Invalid poppy configuration: each domain that the "domains" function returns must be a non-blank string';
const POPPY_DOMAINS_INVALID_DOMAIN_MESSAGE =
  'Invalid poppy configuration: the "domains" function returned a domain that is not valid: ';

/**
 * Projects an exchange result or a cached entry onto the public result shape.
 *
 * `scope` is replayed exactly as the authorization server sent it, and the key is left
 * out entirely when there was none, so a cache hit is indistinguishable from the call
 * that populated it.
 */
function toOnBehalfOfTokenResult(
  token: Pick<TokenExchangeProfileResult, 'accessToken' | 'expiresAt' | 'scope' | 'tokenType' | 'issuedTokenType'>,
  grantedScopes: string[]
): OnBehalfOfTokenResult {
  return {
    accessToken: token.accessToken,
    expiresAt: token.expiresAt,
    grantedScopes: [...grantedScopes],
    ...(token.scope !== undefined ? { scope: token.scope } : {}),
    ...(token.tokenType !== undefined ? { tokenType: token.tokenType } : {}),
    ...(token.issuedTokenType !== undefined ? { issuedTokenType: token.issuedTokenType } : {}),
  };
}

/**
 * Reads the `cnf.jkt` confirmation thumbprint from verified claims, or `undefined` when the
 * token is not bound to a key. The challenge scheme of a DPoP-bound token follows from it.
 */
function getConfirmationThumbprint(claims: object): string | undefined {
  const cnf = (claims as { cnf?: unknown }).cnf;

  if (cnf && typeof cnf === 'object') {
    const jkt = (cnf as Record<string, unknown>).jkt;
    return typeof jkt === 'string' ? jkt : undefined;
  }

  return undefined;
}

function normalizeDomain(value: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('domain must be a non-empty string');
  }

  const trimmed = value.trim();
  let withScheme: string;
  if (/^https?:\/\//i.test(trimmed)) {
    if (!/^https:\/\//i.test(trimmed)) {
      throw new Error('invalid domain URL (https required)');
    }
    withScheme = trimmed;
  } else {
    withScheme = `https://${trimmed}`;
  }
  let domainUrl: URL;
  try {
    domainUrl = new URL(withScheme);
  } catch {
    throw new Error('invalid domain URL');
  }

  if (domainUrl.username || domainUrl.password) {
    throw new Error('invalid domain URL (credentials are not allowed)');
  }

  if (domainUrl.search || domainUrl.hash) {
    throw new Error('invalid domain URL (query/fragment are not allowed)');
  }

  domainUrl.hash = '';
  domainUrl.search = '';
  domainUrl.hostname = domainUrl.hostname.toLowerCase();

  if (domainUrl.pathname && domainUrl.pathname !== '/' && domainUrl.pathname !== '') {
    throw new Error('invalid domain URL (path segments are not allowed)');
  }

  domainUrl.pathname = '/';

  return domainUrl.toString();
}

/**
 * Normalizes what a `domains` function returned for a Poppy request, with the rules of `verifyAccessToken`. A result
 * that breaks them is a mistake of the setup, and not of the agent, so it throws `InvalidConfigurationError`. An empty
 * array is not a mistake: it says that no issuer is allowed for this request, so the Session JWT is refused.
 */
function normalizeResolvedDomains(resolved: unknown): string[] {
  if (!Array.isArray(resolved)) {
    throw new InvalidConfigurationError(POPPY_DOMAINS_NOT_ARRAY_MESSAGE);
  }

  return resolved.map((domain: unknown) => {
    if (typeof domain !== 'string' || !domain.trim()) {
      throw new InvalidConfigurationError(POPPY_DOMAINS_NOT_STRING_MESSAGE);
    }
    try {
      return normalizeDomain(domain);
    } catch (error) {
      // The messages of `normalizeDomain` are fixed texts that never repeat the domain.
      throw new InvalidConfigurationError(`${POPPY_DOMAINS_INVALID_DOMAIN_MESSAGE}${(error as Error).message}`);
    }
  });
}

function normalizeAlgorithms(algorithms: string[] | undefined): string[] {
  if (algorithms === undefined) {
    return ['RS256'];
  }

  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new InvalidConfigurationError('Invalid algorithms configuration: "algorithms" must be a non-empty array');
  }

  const normalized: string[] = [];
  for (const algorithm of algorithms) {
    if (typeof algorithm !== 'string' || !algorithm.trim()) {
      throw new InvalidConfigurationError(
        'Invalid algorithms configuration: each "algorithms" entry must be a non-empty string'
      );
    }
    const trimmed = algorithm.trim();
    if (trimmed.toUpperCase().startsWith('HS')) {
      throw new InvalidConfigurationError(
        'Invalid algorithms configuration: symmetric algorithms are not allowed'
      );
    }
    normalized.push(trimmed);
  }

  return Array.from(new Set(normalized));
}
