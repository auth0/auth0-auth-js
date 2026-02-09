import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, jwtVerify, customFetch } from 'jose';
import { AuthClient, TokenForConnectionError, MissingClientAuthError } from '@auth0/auth0-auth-js';
import {
  AccessTokenForConnectionOptions,
  ApiClientOptions,
  ConnectionTokenSet,
  DPoPOptions,
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

export class ApiClient {
  #serverMetadata: oauth.AuthorizationServer | undefined;
  readonly #options: ApiClientOptions;
  #jwks?: ReturnType<typeof createRemoteJWKSet>;
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

    this.#options = options;

    if (options.clientId) {
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
  async #discover() {
    if (this.#serverMetadata) {
      return {
        serverMetadata: this.#serverMetadata,
      };
    }

    const issuer = new URL(`https://${this.#options.domain}`);
    const response = await oauth.discoveryRequest(issuer, {
      [oauth.customFetch]: this.#options.customFetch,
    });

    this.#serverMetadata = await oauth.processDiscoveryResponse(issuer, response);

    return {
      serverMetadata: this.#serverMetadata,
    };
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

    const { serverMetadata } = await this.#discover();

    this.#jwks ||= createRemoteJWKSet(new URL(serverMetadata!.jwks_uri!), {
      [customFetch]: this.#options.customFetch,
    });

    try {
      const { payload } = await jwtVerify(options.accessToken, this.#jwks, {
        issuer: this.#serverMetadata!.issuer,
        audience: this.#options.audience,
        algorithms: options.algorithms ?? ['RS256'],
        requiredClaims: ['iat', 'exp', ...(options.requiredClaims || [])],
      });

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
