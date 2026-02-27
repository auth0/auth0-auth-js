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
  TokenExchangeProfileResult,
  VerifyAccessTokenOptions,
} from './types.js';
import {
  AuthError,
  InvalidConfigurationError,
  InvalidDpopProofError,
  InvalidRequestError,
  MissingRequiredArgumentError,
  VerifyAccessTokenError,
} from './errors.js';
import { ALLOWED_DPOP_ALGORITHMS, buildChallenges, verifyDpopProof } from './dpop-api.js';
import { LruCache } from './lru-cache.js';

export class ApiClient {
  readonly #serverMetadataByDomain: LruCache<oauth.AuthorizationServer>;
  readonly #options: ApiClientOptions;
  readonly #jwksByUri: LruCache<ReturnType<typeof createRemoteJWKSet>>;
  readonly #domains?: string[] | DomainsResolver;
  readonly #algorithms: string[];
  readonly #defaultDomainUrl?: string;
  readonly #authClient: AuthClient | undefined;

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
  async verifyAccessToken(options: VerifyAccessTokenOptions) {
    const mode: NonNullable<DPoPOptions['mode']> = this.#options.dpop?.mode ?? 'allowed';
    // Default timing options
    const iatOffset = this.#options.dpop?.iatOffset ?? 300;
    const iatLeeway = this.#options.dpop?.iatLeeway ?? 30;

    // Normalize scheme to lowercase; default to 'bearer' if not provided.
    const scheme = (options.scheme ?? 'bearer').toLowerCase();
    const dpopProof = options.dpopProof;
    const httpMethod = options.httpMethod;
    const httpUrl = options.httpUrl;
    const hasDpopParams = dpopProof !== undefined || httpMethod !== undefined || httpUrl !== undefined;

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

    // When `scheme` is not provided,  but `dpopProof`, `httpMethod`, or `httpUrl` are present.
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
    const requestUrl = options.url ?? options.httpUrl;
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
          url: requestUrl,
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
        const { issuer, jwksUri } = this.#requireDiscoveryMetadata(matchedDomain, serverMetadata, mode, scheme);
        issuerForVerify = issuer;
        jwks = this.#getJwksForDomain(jwksUri);
      } else {
        const domainUrl = defaultDomainUrl as string;
        const { serverMetadata } = await this.#discoverDomain(domainUrl);
        const { issuer, jwksUri } = this.#requireDiscoveryMetadata(domainUrl, serverMetadata, mode, scheme);
        issuerForVerify = issuer;
        jwks = this.#getJwksForDomain(jwksUri);
      }

      const jwtVerifyOptions: Parameters<typeof jwtVerify>[2] = {
        audience: this.#options.audience,
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
        return payload;
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

      return payload;
    } catch (e) {
      if (e instanceof AuthError) {
        throw e;
      }
      const message = e instanceof Error ? e.message : String(e);
      const err = new VerifyAccessTokenError(message);
      throw this.#addChallenges(err, mode, scheme);
    }
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
    domain: string,
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
      ...(response.scope && { scope: response.scope }),
      ...(response.idToken && { idToken: response.idToken }),
      ...(response.refreshToken && { refreshToken: response.refreshToken }),
      ...(response.tokenType && { tokenType: response.tokenType }),
      ...(response.issuedTokenType && { issuedTokenType: response.issuedTokenType }),
    };
  }
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
      throw new InvalidConfigurationError('Invalid algorithms configuration: "algorithms" must be a non-empty array');
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
