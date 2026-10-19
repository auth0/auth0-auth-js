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
  ScopeMatching,
  TokenExchangeProfileResult,
  VerifyAccessTokenOptions,
  VerifiedAccessTokenClaims,
} from './types.js';
import {
  AuthError,
  InvalidConfigurationError,
  InvalidDpopProofError,
  InvalidRequestError,
  MissingRequiredArgumentError,
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
  OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS,
  readOboCachedToken,
  writeOboCachedToken,
  type OboCacheAccess,
} from './obo-cache.js';
import { ALLOWED_DPOP_ALGORITHMS, buildChallenges, verifyDpopProof } from './dpop-api.js';
import { LruCache } from './lru-cache.js';

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

    if (!this.#options.audience) {
      throw new MissingRequiredArgumentError('audience');
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

      let cnfJkt: string | undefined;
      const cnf = (payload as Record<string, unknown> & { cnf?: unknown }).cnf;

      // Extract `jkt` from `cnf` claim if present
      if (cnf && typeof cnf === 'object') {
        const maybeJkt = (cnf as Record<string, unknown>).jkt;
        if (typeof maybeJkt === 'string') {
          cnfJkt = maybeJkt;
        }
      }

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
      ...(response.idToken !== undefined ? { idToken: response.idToken } : {}),
      ...(response.refreshToken !== undefined ? { refreshToken: response.refreshToken } : {}),
      ...(response.tokenType !== undefined ? { tokenType: response.tokenType } : {}),
      ...(response.issuedTokenType !== undefined ? { issuedTokenType: response.issuedTokenType } : {}),
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
   * A store failure never fails this call. A read that throws, a malformed entry and an
   * entry close to expiry are all treated as a cache miss, and a write that throws still
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
   * rejected otherwise:
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
   * @throws {InvalidConfigurationError} When `context.verified` does not match `accessToken`,
   * when its claims were not returned by `verifyAccessToken` on this same `ApiClient`
   * instance (object identity is required, so a clone or deserialized copy is rejected), or
   * when its claims have expired
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
      throw new InvalidConfigurationError(
        'The "verified" context does not match the access token being exchanged.'
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

    const result = await this.getTokenByExchangeProfile(accessToken, {
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
      this.#assertOrganizationPolicyEnforceable();
      // On this path the claims come from the copy recorded when this instance verified
      // the token, never from the object the caller passed. The caller's object is only
      // used to look that record up. Mutating it, before or after this call, therefore
      // cannot change the cache key: the key is derived from what was actually verified.
      claims = this.#assertPreVerifiedTrusted(context.verified, accessToken);
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
   * Rejects a caller-supplied pre-verified token unless this instance produced its claims
   * from the same token string and the claims are still unexpired. The caller has
   * already checked that the token string equals the one being exchanged.
   *
   * Returns the copy of the claims recorded at verification time. Callers must use that
   * copy and never the supplied object.
   */
  #assertPreVerifiedTrusted(verified: VerifiedToken, accessToken: string): VerifiedAccessTokenClaims {
    const supplied = verified.claims as object | null | undefined;
    const record = typeof supplied === 'object' && supplied !== null ? this.#verifiedClaims.get(supplied) : undefined;

    if (record === undefined || record.accessToken !== verified.accessToken || verified.accessToken !== accessToken) {
      throw new InvalidConfigurationError(
        'The "verified" context must hold the claims object returned by verifyAccessToken on this same ApiClient instance for this access token.'
      );
    }

    const claims = record.claims;
    const exp = (claims as { exp?: unknown }).exp;
    const nowSeconds = Math.floor(Date.now() / 1000);

    if (typeof exp !== 'number' || !Number.isFinite(exp) || exp <= nowSeconds + OBO_CACHE_CLOCK_SKEW_LEEWAY_SECONDS) {
      throw new InvalidConfigurationError('The "verified" context holds claims that have expired.');
    }

    return claims;
  }

  /**
   * Organization policy is enforced during access token verification. A caller-supplied
   * pre-verified token skips that verification, so the policy has to be re-asserted
   * against the supplied claims instead.
   *
   * This branch does not carry organization policy: it belongs to the change that adds
   * the `organizationPolicy` and `organizationId` options, which is a prerequisite of
   * this one. Until that lands, the combination is refused rather than silently allowed
   * through unchecked.
   *
   * MERGE-TIME RECONCILE: replace the throw below with the organization-policy
   * enforcement that `verifyAccessToken` performs, applied to the supplied claims.
   */
  #assertOrganizationPolicyEnforceable(): void {
    const policy = (this.#options as { organizationPolicy?: unknown }).organizationPolicy;

    if (policy === undefined) {
      return;
    }

    throw new InvalidConfigurationError(
      'A pre-verified token cannot be used while "organizationPolicy" is configured, because the organization policy is enforced during access token verification.'
    );
  }
}

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
