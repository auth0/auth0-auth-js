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
 * const updatedSession = await authClient.anonymous.getTokenSilently(session, {
 *   audience: 'https://api.example.com',
 * });
 *
 * // End the session
 * await authClient.anonymous.logout(updatedSession.sessionToken);
 * ```
 */
export class AnonymousSessionClient {
  readonly #baseUrl: string;
  readonly #clientId: string;
  readonly #customFetch: typeof fetch;

  /**
   * @internal
   */
  constructor(options: AnonymousSessionClientOptions) {
    this.#baseUrl = `https://${options.domain}`;
    this.#clientId = options.clientId;
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
   * Obtains a new access token for an existing anonymous session.
   *
   * Calls `POST /anonymous/token` with the current session token to re-mint a
   * short-lived access token. The anonymous identity and session token remain
   * unchanged. Metadata cannot be passed on re-mint.
   *
   * @param sessionToken - The session token from a previously created anonymous session
   * @param options - Options for the renewed token
   * @param options.audience - The API audience to scope the access token to
   * @param options.scope - Space-separated list of scopes to request
   * @returns An updated session with a fresh access token and the same session token
   * @throws {AnonymousSessionError} When the request fails, including `session_expired`
   *   or `invalid_session_token` if the session token is no longer valid
   *
   * @example
   * ```typescript
   * const refreshed = await authClient.anonymous.getToken(session.sessionToken, {
   *   audience: 'https://api.example.com',
   * });
   * ```
   */
  async getToken(sessionToken: string, options?: GetAnonymousTokenSilentlyOptions): Promise<AnonymousSession> {
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
   * Returns a valid anonymous session, creating or renewing it as needed.
   *
   * Implements the full token renewal lifecycle:
   * 1. If `session` is `null` — creates a new anonymous session.
   * 2. If the access token is still valid — returns the session unchanged.
   * 3. If the access token is expired — re-mints it using the session token.
   * 4. If the session token has also expired (`session_expired` or
   *    `invalid_session_token`) — silently creates a fresh anonymous session.
   *    **Any metadata previously attached to the session is permanently lost.**
   * 5. For all other errors — throws an {@link AnonymousSessionError}.
   *
   * @param session - The current anonymous session, or `null` if none exists
   * @param options - Options for the token request
   * @param options.audience - The API audience to scope the access token to
   * @param options.scope - Space-separated list of scopes to request
   * @returns A valid anonymous session (may be the same object, renewed, or brand-new)
   * @throws {AnonymousSessionError} For non-recoverable errors
   *
   * @example
   * ```typescript
   * // Stored session from a previous visit (may or may not be expired)
   * let session = loadSessionFromStorage();
   *
   * session = await authClient.anonymous.getTokenSilently(session, {
   *   audience: 'https://api.example.com',
   * });
   *
   * // session.accessToken is guaranteed to be valid at this point
   * ```
   */
  async getTokenSilently(
    session: AnonymousSession | null,
    options?: GetAnonymousTokenSilentlyOptions
  ): Promise<AnonymousSession> {
    // No session — create one from scratch
    if (!session) {
      return this.createSession(options);
    }

    // Access token is still valid — nothing to do
    const now = Math.floor(Date.now() / 1000);
    if (session.expiresAt > now) {
      return session;
    }

    // Access token expired — try to re-mint using the session token
    try {
      return await this.getToken(session.sessionToken, options);
    } catch (e) {
      if (e instanceof AnonymousSessionError && SESSION_INVALIDATION_CODES.has(e.code)) {
        // Session token also expired or invalid — silently start a fresh session.
        // Any metadata attached to the old session is permanently lost.
        return this.createSession(options);
      }
      throw e;
    }
  }

  /**
   * Ends an anonymous session.
   *
   * Calls `POST /anonymous/logout` to invalidate the session on Auth0's side.
   * After this call the session token can no longer be used to mint access tokens.
   *
   * Note: Any access tokens issued before logout remain valid until they naturally
   * expire. There is no server-side session store to revoke them from.
   *
   * @param sessionToken - The session token of the anonymous session to end
   * @returns Promise that resolves when the session has been ended
   * @throws {AnonymousSessionError} When the request fails
   *
   * @example
   * ```typescript
   * await authClient.anonymous.logout(session.sessionToken);
   * ```
   */
  async logout(sessionToken: string): Promise<void> {
    const url = `${this.#baseUrl}/anonymous/logout`;

    const response = await this.#customFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({
        client_id: this.#clientId,
        session_token: sessionToken,
      }),
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
