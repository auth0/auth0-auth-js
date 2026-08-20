import { AnonymousSessionError, type AnonymousSessionApiErrorResponse } from './errors.js';
import type {
  AnonymousSessionClientOptions,
  AnonymousSession,
  AnonymousTokens,
  AnonymousTokenApiResponse,
  CreateAnonymousSessionOptions,
  GetAnonymousTokenSilentlyOptions,
} from './types.js';

/**
 * Error codes that indicate the session token is no longer valid.
 * When these are received during token renewal, the SDK silently creates
 * a fresh anonymous session instead of surfacing an error.
 */
const SESSION_INVALIDATION_CODES = new Set(['session_expired', 'invalid_session_token']);

/**
 * Parses an Auth0 token API response into an {@link AnonymousTokens} object.
 */
function parseTokenResponse(apiResponse: AnonymousTokenApiResponse): AnonymousTokens {
  const now = Math.floor(Date.now() / 1000);
  if (typeof apiResponse.access_token !== 'string' || !apiResponse.access_token) {
    throw new AnonymousSessionError('server_error', 'access_token missing or invalid in anonymous token response');
  }
  const expiresIn = apiResponse.expires_in;
  if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn)) {
    throw new AnonymousSessionError('server_error', 'expires_in missing or invalid in anonymous token response');
  }
  return {
    accessToken: apiResponse.access_token,
    expiresIn,
    expiresAt: now + expiresIn,
    scope: apiResponse.scope,
    sessionToken: apiResponse.session_token,
  };
}

/**
 * Reads and parses an error response body, falling back to a generic error shape
 * if the body cannot be parsed as JSON.
 */
async function parseErrorResponse(response: Response): Promise<AnonymousSessionApiErrorResponse> {
  try {
    return (await response.json()) as AnonymousSessionApiErrorResponse;
  } catch {
    return {
      error: 'server_error',
      error_description: `Request failed with status ${response.status}`,
    };
  }
}

/**
 * Client for anonymous session operations.
 *
 * Provides low-level HTTP calls to the Auth0 anonymous session endpoints as well
 * as a higher-level {@link getTokenSilently} method that implements the renewal
 * logic: if the access token is expired it re-mints it from the session token;
 * if the session token itself has expired a fresh anonymous session is created
 * silently (any metadata previously set on the session is lost at that point).
 *
 * This client is exposed on {@link AuthClient} as `authClient.anonymous`.
 *
 * **Prerequisites:**
 * - The tenant must have the `anonymous_sessions_enabled` feature flag enabled.
 * - The client ID must be configured for anonymous sessions via the Management API.
 * - Any resource server you want to call with an anonymous token must have
 *   `allow_anonymous_access: true` and a `subject_type_authorization` policy set.
 *
 * @example
 * ```typescript
 * // Create a session
 * const session = await authClient.anonymous.createSession({
 *   audience: 'https://api.example.com',
 *   metadata: { referral: 'homepage' },
 * });
 *
 * // Later, get a valid access token (renews automatically if expired)
 * const updatedSession = await authClient.anonymous.getTokenSilently({
 *   sessionToken: session.sessionToken,
 *   audience: 'https://api.example.com',
 * });
 *
 * // End the session
 * await authClient.anonymous.logout();
 * ```
 */
export class AnonymousSessionClient {
  readonly #baseUrl: string;
  readonly #clientId: string;
  readonly #clientSecret?: string;
  readonly #customFetch: typeof fetch;

  /**
   * @internal
   */
  constructor(options: AnonymousSessionClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
    this.#clientSecret = options.clientSecret;
    this.#customFetch = options.customFetch ?? ((...args) => fetch(...args));
  }

  /**
   * Creates a new anonymous session.
   *
   * Calls `POST /anonymous/token` without a session token to establish a fresh
   * anonymous identity. Returns a session containing both the session token (for
   * future renewal) and an access token (for calling APIs).
   *
   * Optionally accepts up to 1 KB of metadata that is attached to the anonymous
   * identity at creation time. Metadata is **set once** and cannot be changed
   * after the session is created.
   *
   * @param options - Options for the new session
   * @param options.audience - The API audience to scope the access token to
   * @param options.scope - Space-separated list of scopes to request
   * @param options.metadata - Up to 1 KB of key-value metadata (set-once)
   * @returns The newly created anonymous session
   * @throws {AnonymousSessionError} When the request fails
   *
   * @example
   * ```typescript
   * const session = await authClient.anonymous.createSession({
   *   audience: 'https://api.example.com',
   *   metadata: { source: 'landing-page' },
   * });
   * ```
   */
  async createSession(options?: CreateAnonymousSessionOptions): Promise<AnonymousSession> {
    const body: Record<string, unknown> = {
      client_id: this.#clientId,
    };

    if (options?.audience) {
      body.audience = options.audience;
    }
    if (options?.scope) {
      body.scope = options.scope;
    }
    if (options?.metadata) {
      body.metadata = options.metadata;
    }

    const tokens = await this.#postAnonymousToken(body);

    if (!tokens.sessionToken) {
      throw new AnonymousSessionError('server_error', 'session_token missing from create session response');
    }

    return {
      sessionToken: tokens.sessionToken,
      accessToken: tokens.accessToken,
      expiresAt: tokens.expiresAt,
      scope: tokens.scope,
    };
  }

  /**
   * Returns a valid anonymous session, creating or renewing it as needed.
   *
   * This is the primary entry point for obtaining an anonymous access token.
   * The calling SDK (auth0-spa-js, auth0-server-js) is responsible for checking
   * token expiry and deciding when to call this method.
   *
   * Behaviour:
   * 1. No `sessionToken` — creates a fresh anonymous session.
   * 2. `sessionToken` provided — re-mints the access token for the existing session.
   * 3. If the session token has expired (`session_expired` or `invalid_session_token`)
   *    — silently creates a fresh anonymous session instead.
   *    **Any metadata previously attached to the session is permanently lost.**
   * 4. For all other errors — throws an {@link AnonymousSessionError}.
   *
   * @param options - Options for the token request
   * @param options.sessionToken - The session token from an existing anonymous session.
   *   Omit to create a new session.
   * @param options.audience - The API audience to scope the access token to
   * @param options.scope - Space-separated list of scopes to request
   * @returns A valid anonymous session (may be newly created or renewed)
   * @throws {AnonymousSessionError} For non-recoverable errors
   *
   * @example
   * ```typescript
   * // First visit — no session yet
   * const session = await authClient.anonymous.getTokenSilently({
   *   audience: 'https://api.example.com',
   * });
   *
   * // Subsequent visit — renew existing session token
   * const renewed = await authClient.anonymous.getTokenSilently({
   *   sessionToken: storedSessionToken,
   *   audience: 'https://api.example.com',
   * });
   * ```
   */
  async getTokenSilently(options?: GetAnonymousTokenSilentlyOptions): Promise<AnonymousSession> {
    if (!options?.sessionToken) {
      return this.createSession({ audience: options?.audience, scope: options?.scope });
    }

    try {
      return await this.#mintToken(options.sessionToken, options);
    } catch (e) {
      if (e instanceof AnonymousSessionError && SESSION_INVALIDATION_CODES.has(e.code)) {
        // Session token expired or invalid — silently start a fresh session.
        // Any metadata attached to the old session is permanently lost.
        return this.createSession({ audience: options?.audience, scope: options?.scope });
      }
      throw e;
    }
  }

  /**
   * Re-mints an access token for an existing anonymous session.
   * Internal — callers use {@link getTokenSilently} instead.
   */
  async #mintToken(sessionToken: string, options?: GetAnonymousTokenSilentlyOptions): Promise<AnonymousSession> {
    const body: Record<string, unknown> = {
      client_id: this.#clientId,
      session_token: sessionToken,
    };

    if (options?.audience) {
      body.audience = options.audience;
    }
    if (options?.scope) {
      body.scope = options.scope;
    }

    const tokens = await this.#postAnonymousToken(body);

    return {
      sessionToken,
      accessToken: tokens.accessToken,
      expiresAt: tokens.expiresAt,
      scope: tokens.scope,
    };
  }

  /**
   * Ends an anonymous session.
   *
   * Calls `POST /anonymous/logout`. Auth0 identifies the session via the
   * `auth0_anon` cookie (sent automatically through `credentials: 'include'`)
   * and clears it in the response. If the cookie is not cleared, it is sent to
   * `/authorize` on the next login, re-attaching the anonymous identity to the
   * authenticated user.
   *
   * When called server-side (e.g. via auth0-server-js), the user's browser
   * cookie is not forwarded to Auth0 and the `Set-Cookie` clear response does
   * not reach the browser — the higher-level SDK must handle cookie proxying.
   *
   * Issued access tokens are not revoked and remain valid until natural expiry.
   *
   * @returns Promise that resolves when the logout request succeeds
   * @throws {AnonymousSessionError} When the request fails
   *
   * @example
   * ```typescript
   * await authClient.anonymous.logout();
   * ```
   */
  async logout(): Promise<void> {
    const url = `${this.#baseUrl}/anonymous/logout`;

    const body: Record<string, unknown> = {
      client_id: this.#clientId,
    };

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorBody = await parseErrorResponse(response);
      throw new AnonymousSessionError(
        errorBody.error,
        errorBody.error_description || 'Failed to end anonymous session',
        errorBody
      );
    }
  }

  /**
   * Shared helper that calls `POST /anonymous/token` and returns parsed tokens.
   */
  async #postAnonymousToken(body: Record<string, unknown>): Promise<AnonymousTokens> {
    const url = `${this.#baseUrl}/anonymous/token`;

    if (this.#clientSecret) {
      body.client_secret = this.#clientSecret;
    }

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorBody = await parseErrorResponse(response);
      throw new AnonymousSessionError(
        errorBody.error,
        errorBody.error_description || 'Anonymous token request failed',
        errorBody
      );
    }

    let apiResponse: AnonymousTokenApiResponse;
    try {
      apiResponse = (await response.json()) as AnonymousTokenApiResponse;
    } catch {
      throw new AnonymousSessionError('server_error', 'Invalid response from anonymous token endpoint');
    }
    return parseTokenResponse(apiResponse);
  }
}
