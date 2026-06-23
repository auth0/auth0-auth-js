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
   * @param options User profile data and optional realm/organization.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge.
   *
   * @returns A promise resolving to the signup challenge.
   */
  async register(options: PasskeyRegisterOptions, storeOptions?: TStoreOptions): Promise<PasskeyRegisterResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    return authClient.passkey.register(options);
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
   * @param options Optional realm/organization configuration.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {PasskeyChallengeError} If there was an issue requesting the login challenge.
   *
   * @returns A promise resolving to the login challenge.
   */
  async challenge(options?: PasskeyChallengeOptions, storeOptions?: TStoreOptions): Promise<PasskeyChallengeResponse> {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    return authClient.passkey.challenge(options);
  }

  /**
   * Completes a passkey authentication flow (signup or login) by exchanging the
   * WebAuthn credential for tokens, and persists the resulting session.
   *
   * Call this after obtaining a credential from `navigator.credentials.create()`
   * (signup) or `navigator.credentials.get()` (login), passing the `authSession`
   * returned by `register()` / `challenge()` together with the serialized credential.
   *
   * In resolver (multi-tenant) mode, pass the same `storeOptions` you passed to
   * `register()` / `challenge()` so the token exchange resolves the same tenant
   * that issued the `authSession`; otherwise the exchange will fail.
   *
   * @param options The auth session, serialized credential, and optional realm/scope/audience/organization.
   * @param storeOptions Optional options used to pass to the State Store (and to resolve the domain in resolver mode).
   *
   * @throws {PasskeyGetTokenError} If there was an issue exchanging the credential for tokens. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`. No session is persisted in this case.
   * @throws {OrganizationValidationError} When `organization` is passed and the returned ID token's organization claim is missing or does not match. The error is thrown before the session is written, so no session is persisted in this case.
   *
   * @returns A promise resolving to an object containing the authorizationDetails (when RAR was used).
   */
  async getToken(options: PasskeyGetTokenOptions, storeOptions?: TStoreOptions): Promise<PasskeyGetTokenResult> {
    const scope = ensureOpenIdScope(options.scope ?? this.#options.defaultScope);
    const audience = options.audience ?? this.#options.defaultAudience;

    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    const tokenEndpointResponse = await authClient.passkey.getTokenByPasskey({
      ...options,
      scope,
      audience,
    });

    const existingStateData = await this.#options.stateStore.get(this.#options.stateStoreIdentifier, storeOptions);

    const stateData = updateStateData(audience ?? 'default', existingStateData, tokenEndpointResponse, { domain });

    await this.#options.stateStore.set(this.#options.stateStoreIdentifier, stateData, true, storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }
}
