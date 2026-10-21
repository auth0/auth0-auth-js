import { updateStateData } from '../state/utils.js';
import { ensureOpenIdScope } from '../utils.js';
import type { ServerPasskeyClientOptions } from './types.js';
import type {
  PasskeyRegisterOptions,
  PasskeyRegisterResponse,
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyGetTokenOptions,
  PasskeyGetTokenResult,
} from '../types.js';
import type { RequestOptions } from '@auth0/auth0-auth-js';

/** @category Sub-clients */
export class ServerPasskeyClient<TStoreOptions = unknown> {
  readonly #options: ServerPasskeyClientOptions<TStoreOptions>;

  /**
   * @internal
   */
  constructor(options: ServerPasskeyClientOptions<TStoreOptions>) {
    this.#options = options;
  }

  /**
   * Requests a passkey signup challenge for a new user.
   *
   * Returns the `authSession` and the WebAuthn credential creation options
   * (`authnParamsPublicKey`). The application must return these to the browser,
   * pass `authnParamsPublicKey` to `navigator.credentials.create()`, and then
   * call `getToken()` with the resulting credential to complete signup.
   *
   * This method does not create a session; no state is persisted.
   *
   * When the connection requires the user's email address or phone number to be
   * verified, the response includes `verificationRequired` (for example
   * `['email', 'phone']`), and Auth0 sends a one-time code to each listed
   * identifier during this call. `verificationRequired` is absent when no
   * verification is required.
   *
   * `deliveryMethod` (`'text'` or `'voice'`) chooses how the phone code is
   * delivered. Leave it out to let Auth0 use the channel the connection supports
   * (SMS when it supports both or none). Auth0 rejects a channel that the
   * connection does not support with `invalid_request`.
   *
   * Every call starts a separate attempt with its own `authSession` and, when
   * verification is required, sends new codes. To recover from a wrong code,
   * retry `getToken()` instead of calling this again. Do not rely only on Auth0's
   * limits: rate-limit the route that calls this method yourself, per IP address
   * and per email address or phone number.
   *
   * On a confidential client this endpoint accepts `client_secret` as its only
   * credential, so configure `clientSecret` on the `ServerClient`. It does not
   * accept a private key JWT and is not served on the mTLS endpoint aliases, so a
   * client configured with only `clientAssertionSigningKey` or only `useMtls` is
   * rejected by Auth0. Public clients authenticate with `clientId` alone.
   *
   * @param options User profile data, optional realm/organization, and an optional `deliveryMethod` for the phone code.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the signup challenge request. Use headers to forward the end user's IP address as auth0-forwarded-for.
   *
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge, for example when a one-time code could not be sent. `statusCode` holds the HTTP status, which is 429 when the request is rate limited.
   *
   * @returns A promise resolving to the signup challenge.
   */
  async register(options: PasskeyRegisterOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<PasskeyRegisterResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    return authClient.passkey.register(options, requestOptions);
  }

  /**
   * Requests a passkey login challenge for an existing user.
   *
   * Returns the `authSession` and the WebAuthn credential request options
   * (`authnParamsPublicKey`). The application must return these to the browser,
   * pass `authnParamsPublicKey` to `navigator.credentials.get()`, and then
   * call `getToken()` with the resulting credential to complete login.
   *
   * This method does not create a session; no state is persisted.
   *
   * Client authentication works the same way as {@link ServerPasskeyClient.register}:
   * on a confidential client, only a `clientSecret` is accepted here.
   *
   * @param options Optional realm/organization configuration.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the login challenge request.
   *
   * @throws {PasskeyChallengeError} If there was an issue requesting the login challenge.
   *
   * @returns A promise resolving to the login challenge.
   */
  async challenge(options?: PasskeyChallengeOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<PasskeyChallengeResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    return authClient.passkey.challenge(options, requestOptions);
  }

  /**
   * Completes a passkey authentication flow (signup or login) by exchanging the
   * WebAuthn credential for tokens, and persists the resulting session.
   *
   * Call this after obtaining a credential from `navigator.credentials.create()`
   * (signup) or `navigator.credentials.get()` (login), passing the `authSession`
   * returned by `register()` / `challenge()` together with the serialized credential.
   *
   * For a signup where `register()` returned `verificationRequired`, pass the codes
   * the user entered in `verification`, for example `{ email: '123456' }`. Omit it
   * otherwise, including on login.
   *
   * On a wrong code this throws a `PasskeyGetTokenError` whose `isRetryable` is
   * `true`, whose `authSession` is set and whose `verificationRequired` lists the
   * identifiers still needing a code. Call again with the same `authSession` and
   * `credential`, sending codes only for those identifiers.
   *
   * In resolver (multi-tenant) mode, pass `storeOptions` that make the domain
   * resolver return the same domain as for `register()` / `challenge()`, on every
   * retry as well, so the token exchange resolves the tenant that issued the
   * `authSession`; otherwise the exchange will fail.
   *
   * @param options The auth session, serialized credential, optional realm/scope/audience/organization, and the `verification` codes when `register()` returned `verificationRequired`.
   * @param storeOptions Optional options used to pass to the State Store (and to resolve the domain in resolver mode).
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the token exchange. Use headers to forward the end user's IP address as auth0-forwarded-for.
   *
   * @throws {PasskeyGetTokenError} If there was an issue exchanging the credential for tokens. No session is persisted. When `isRetryable` is `true`, retry as described above. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`. Otherwise the attempt is usually over, so start again with `register()` or `challenge()`. A temporary failure, such as rate limiting (`statusCode` 429), can leave it open.
   * @throws {OrganizationValidationError} When `organization` is passed and the returned ID token's organization claim is missing or does not match. The error is thrown before the session is written, so no session is persisted in this case.
   *
   * @returns A promise resolving to an object containing the authorizationDetails (when RAR was used).
   */
  async getToken(options: PasskeyGetTokenOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<PasskeyGetTokenResult> {
    const scope = ensureOpenIdScope(options.scope ?? this.#options.defaultScope);
    const audience = options.audience ?? this.#options.defaultAudience;

    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    const tokenEndpointResponse = await authClient.passkey.getTokenByPasskey({
      ...options,
      scope,
      audience,
    }, requestOptions);

    const existingStateData = await this.#options.stateStore.get(this.#options.stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(audience ?? 'default', existingStateData, tokenEndpointResponse, { domain });

    await this.#options.stateStore.set(this.#options.stateStoreIdentifier, stateData, true, storeOptions);

    // The visitor is authenticated now, so the anonymous session they may have had is over.
    await this.#options.onUserSessionEstablished?.(storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }
}
