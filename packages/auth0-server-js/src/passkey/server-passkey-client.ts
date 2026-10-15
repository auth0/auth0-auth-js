import { OrganizationValidationError, PasskeyGetTokenError } from '@auth0/auth0-auth-js';
import { MissingRequiredArgumentError, MissingTransactionError } from '../errors.js';
import { updateStateData } from '../state/utils.js';
import { ensureOpenIdScope } from '../utils.js';
import {
  createPasskeyTransaction,
  getPasskeyTransactionExpiresAt,
  isCredentialForChallenge,
  redactAuthSession,
} from './passkey-transaction.js';
import type { PasskeyTransactionData } from './passkey-transaction.js';
import type { ServerPasskeyClientOptions } from './types.js';
import type {
  PasskeyRegisterOptions,
  PasskeyRegisterResponse,
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyCompleteOptions,
  PasskeyGetTokenOptions,
  PasskeyGetTokenResult,
  PasskeyStartLoginResult,
  PasskeyStartSignupResult,
} from '../types.js';
import type { RequestOptions, TokenResponse } from '@auth0/auth0-auth-js';

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
   * This method does not create a session; no state is persisted. To keep the
   * `authSession` on the server instead, use {@link ServerPasskeyClient.startSignup}.
   *
   * On a confidential client this endpoint accepts `client_secret` as its only
   * credential, so configure `clientSecret` on the `ServerClient`. It does not
   * accept a private key JWT and is not served on the mTLS endpoint aliases, so a
   * client configured with only `clientAssertionSigningKey` or only `useMtls` is
   * rejected by Auth0. Public clients authenticate with `clientId` alone.
   *
   * @param options User profile data and optional realm/organization.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge.
   *
   * @returns A promise resolving to the signup challenge.
   */
  async register(options: PasskeyRegisterOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<PasskeyRegisterResponse> {
    const { response } = await this.#register(options, storeOptions, requestOptions);

    return response;
  }

  /**
   * Requests a passkey login challenge for an existing user.
   *
   * Returns the `authSession` and the WebAuthn credential request options
   * (`authnParamsPublicKey`). The application must return these to the browser,
   * pass `authnParamsPublicKey` to `navigator.credentials.get()`, and then
   * call `getToken()` with the resulting credential to complete login.
   *
   * This method does not create a session; no state is persisted. To keep the
   * `authSession` on the server instead, use {@link ServerPasskeyClient.startLogin}.
   *
   * Client authentication works the same way as {@link ServerPasskeyClient.register}:
   * on a confidential client, only a `clientSecret` is accepted here.
   *
   * @param options Optional realm/organization configuration.
   * @param storeOptions Optional options used to resolve the domain (resolver mode).
   *
   * @throws {PasskeyChallengeError} If there was an issue requesting the login challenge.
   *
   * @returns A promise resolving to the login challenge.
   */
  async challenge(options?: PasskeyChallengeOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions): Promise<PasskeyChallengeResponse> {
    const { response } = await this.#challenge(options, storeOptions, requestOptions);

    return response;
  }

  /**
   * Completes a passkey authentication flow (signup or login) by exchanging the
   * WebAuthn credential for tokens, and persists the resulting session.
   *
   * Call this after obtaining a credential from `navigator.credentials.create()`
   * (signup) or `navigator.credentials.get()` (login), passing the `authSession`
   * returned by `register()` / `challenge()` together with the serialized credential.
   * For a flow started with `startSignup()` / `startLogin()`, use
   * {@link ServerPasskeyClient.complete} instead.
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

    return this.#persistSession(domain, audience, tokenEndpointResponse, storeOptions);
  }

  /**
   * Starts a passkey signup for a new user, keeping the `authSession` on the server.
   *
   * Requests a signup challenge like {@link ServerPasskeyClient.register}, then stores the
   * `authSession`, the challenge, the domain, and the `realm` and `organization` in the
   * Transaction Store (with `CookieTransactionStore`, the encrypted `__a0_passkey_tx` cookie).
   * Only what the browser needs is returned: pass `authnParamsPublicKey` to
   * `navigator.credentials.create()`, and send the resulting credential to
   * {@link ServerPasskeyClient.complete}. When `verificationRequired` is present, Auth0 has sent
   * a one-time code to each listed identifier; collect them and pass them to `complete()`.
   *
   * One passkey flow runs per browser at a time: starting a new signup or login replaces the
   * stored one. It expires together with the Auth0 auth session (60 seconds, or 15 minutes with
   * identifier verification).
   *
   * Client authentication works the same way as {@link ServerPasskeyClient.register}:
   * on a confidential client, only a `clientSecret` is accepted here.
   *
   * @param options User profile data and optional realm/organization.
   * @param storeOptions Optional options used to pass to the Transaction Store (and to resolve the domain in resolver mode).
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the signup challenge request.
   *
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge. Nothing is stored in this case.
   * @throws {InvalidConfigurationError} When `passkeyTransactionIdentifier` and another store identifier are a prefix of one another. Auth0 is not called.
   *
   * @returns A promise resolving to the WebAuthn creation options, and `verificationRequired` when identifier verification applies.
   */
  async startSignup(
    options: PasskeyRegisterOptions,
    storeOptions?: TStoreOptions,
    requestOptions?: RequestOptions
  ): Promise<PasskeyStartSignupResult> {
    this.#options.transaction.assertPrefixFree();

    const { domain, response } = await this.#register(options, storeOptions, requestOptions);
    await this.#startTransaction(domain, response, options, storeOptions);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { authSession, ...result } = response;
    return result;
  }

  /**
   * Starts a passkey login for an existing user, keeping the `authSession` on the server.
   *
   * Requests a login challenge like {@link ServerPasskeyClient.challenge}, then stores the
   * `authSession`, the challenge, the domain, and the `realm` and `organization` in the
   * Transaction Store (with `CookieTransactionStore`, the encrypted `__a0_passkey_tx` cookie).
   * Only what the browser needs is returned: pass `authnParamsPublicKey` to
   * `navigator.credentials.get()`, and send the resulting credential to
   * {@link ServerPasskeyClient.complete}.
   *
   * One passkey flow runs per browser at a time: starting a new signup or login replaces the
   * stored one. It expires together with the Auth0 auth session (60 seconds).
   *
   * Client authentication works the same way as {@link ServerPasskeyClient.register}:
   * on a confidential client, only a `clientSecret` is accepted here.
   *
   * @param options Optional realm/organization configuration.
   * @param storeOptions Optional options used to pass to the Transaction Store (and to resolve the domain in resolver mode).
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the login challenge request.
   *
   * @throws {PasskeyChallengeError} If there was an issue requesting the login challenge. Nothing is stored in this case.
   * @throws {InvalidConfigurationError} When `passkeyTransactionIdentifier` and another store identifier are a prefix of one another. Auth0 is not called.
   *
   * @returns A promise resolving to the WebAuthn request options.
   */
  async startLogin(
    options?: PasskeyChallengeOptions,
    storeOptions?: TStoreOptions,
    requestOptions?: RequestOptions
  ): Promise<PasskeyStartLoginResult> {
    this.#options.transaction.assertPrefixFree();

    const { domain, response } = await this.#challenge(options, storeOptions, requestOptions);
    await this.#startTransaction(domain, response, options, storeOptions);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { authSession, ...result } = response;
    return result;
  }

  /**
   * Completes a passkey signup or login started with {@link ServerPasskeyClient.startSignup} or
   * {@link ServerPasskeyClient.startLogin}: exchanges the WebAuthn credential for tokens, and
   * persists the resulting session.
   *
   * The `authSession`, `realm`, `organization` and domain are taken from the stored transaction,
   * never from the request, so the browser only sends the credential (and, for identifier
   * verification, the one-time codes). In resolver mode, the tenant that started the flow is used.
   *
   * The stored transaction is deleted once Auth0 has used the auth session: on success (before the
   * session is written), on `mfa_required`, on an `invalid_grant` without an auth session (used,
   * expired or invalid passkey), and on an organization claim mismatch. It is kept on every other
   * failure, such as a wrong code (`error.isRetryable`), a missing code, a rate limit (429), a server
   * error or a network error, so `complete()` can be called again with the same credential. If Auth0
   * had used the auth session after all, that call fails with `invalid_grant` and deletes it.
   *
   * Deleting or updating the stored transaction after the exchange is best effort, and a Transaction
   * Store error there is not reported: after a success the login still succeeds, and after a failure
   * the original error is thrown. A custom store should log its own failures; see `TransactionStore`.
   *
   * @param options The serialized credential, the one-time codes when `startSignup()` returned `verificationRequired`, and optional scope/audience.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the token exchange.
   *
   * @throws {MissingRequiredArgumentError} When `credential` or its `response.clientDataJSON` is not provided. Auth0 is not called.
   * @throws {MissingTransactionError} When no passkey signup or login is in progress, it has expired, or the credential was created for another challenge (for example in another tab, before a newer start replaced the transaction). Auth0 is not called; start a new flow.
   * @throws {PasskeyGetTokenError} If there was an issue exchanging the credential for tokens. `isRetryable` is `true` for a wrong one-time code: collect new codes for `verificationRequired` and call `complete()` again. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`. No session is persisted in these cases. Unlike with `getToken()`, the error never carries the `authSession`.
   * @throws {OrganizationValidationError} When the flow started with an `organization` and the returned ID token's organization claim is missing or does not match. No session is persisted in this case.
   * @throws {InvalidConfigurationError} When `passkeyTransactionIdentifier` and another store identifier are a prefix of one another. Auth0 is not called.
   *
   * @returns A promise resolving to an object containing the authorizationDetails (when RAR was used).
   */
  async complete(
    options: PasskeyCompleteOptions,
    storeOptions?: TStoreOptions,
    requestOptions?: RequestOptions
  ): Promise<PasskeyGetTokenResult> {
    if (!options?.credential) {
      throw new MissingRequiredArgumentError('credential');
    }

    // Without it, the challenge check below would report a credential from another flow, and starting
    // again would not help.
    const clientDataJSON: unknown = options.credential.response?.clientDataJSON;

    if (typeof clientDataJSON !== 'string' || !clientDataJSON) {
      throw new MissingRequiredArgumentError('credential.response.clientDataJSON');
    }

    const transaction = await this.#options.transaction.read(storeOptions);

    if (!transaction) {
      throw new MissingTransactionError(
        'There is no passkey signup or login in progress, or it has expired. Call `passkey.startSignup()` or `passkey.startLogin()` first.'
      );
    }

    // A credential created for another challenge belongs to an earlier start, for example in another
    // tab, whose transaction was replaced. Sending it would only use up the current auth session.
    if (!isCredentialForChallenge(options.credential, transaction.challenge)) {
      throw new MissingTransactionError(
        'The passkey credential was not created for the passkey signup or login in progress. Call `passkey.startSignup()` or `passkey.startLogin()` to start again.'
      );
    }

    const scope = ensureOpenIdScope(options.scope ?? this.#options.defaultScope);
    const audience = options.audience ?? this.#options.defaultAudience;
    const authClient = this.#options.getAuthClient(transaction.domain);

    let tokenEndpointResponse: TokenResponse;

    try {
      tokenEndpointResponse = await authClient.passkey.getTokenByPasskey({
        authSession: transaction.authSession,
        credential: options.credential,
        verification: options.verification,
        realm: transaction.realm,
        organization: transaction.organization,
        scope,
        audience,
      }, requestOptions);
    } catch (e: unknown) {
      await this.#settleFailedExchange(transaction, e, storeOptions);
      redactAuthSession(e);
      throw e;
    }

    // The auth session is used up. Delete the transaction before writing the session, as
    // `completeInteractiveLogin()` does. Best effort: Auth0 has already issued the tokens (and, for
    // a signup, created the user), so a failing store must not cost the user this login. An entry
    // left behind is answered with `invalid_grant` on a later attempt, which deletes it.
    try {
      await this.#options.transaction.clear(storeOptions);
    } catch {
      // see above
    }

    return this.#persistSession(transaction.domain, audience, tokenEndpointResponse, storeOptions);
  }

  async #register(options: PasskeyRegisterOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions) {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    return { domain, response: await authClient.passkey.register(options, requestOptions) };
  }

  async #challenge(options?: PasskeyChallengeOptions, storeOptions?: TStoreOptions, requestOptions?: RequestOptions) {
    const domain = await this.#options.resolveDomain(storeOptions);
    const authClient = this.#options.getAuthClient(domain);

    return { domain, response: await authClient.passkey.challenge(options, requestOptions) };
  }

  async #startTransaction(
    domain: string,
    response: PasskeyRegisterResponse | PasskeyChallengeResponse,
    options: PasskeyChallengeOptions | undefined,
    storeOptions?: TStoreOptions
  ): Promise<void> {
    const transaction = createPasskeyTransaction({
      authSession: response.authSession,
      challenge: response.authnParamsPublicKey.challenge,
      domain,
      realm: options?.realm,
      organization: options?.organization,
      expiresAt: getPasskeyTransactionExpiresAt(response.authnParamsPublicKey.timeout),
    });

    await this.#options.transaction.write(transaction, storeOptions);
  }

  /**
   * Updates or deletes the transaction after a failed exchange. It is deleted only when Auth0 has
   * surely used the auth session; in every other case it is kept, so a retry can still use it.
   */
  async #settleFailedExchange(transaction: PasskeyTransactionData, error: unknown, storeOptions?: TStoreOptions) {
    try {
      if (error instanceof PasskeyGetTokenError) {
        if (error.isRetryable) {
          // A wrong one-time code. Auth0 keeps the auth session and returns it.
          if (error.authSession && error.authSession !== transaction.authSession) {
            await this.#options.transaction.write(
              createPasskeyTransaction({ ...transaction, authSession: error.authSession }),
              storeOptions
            );
          }
        } else if (error.cause?.error === 'mfa_required' || error.cause?.error === 'invalid_grant') {
          // `mfa_required` comes after the passkey was verified. An `invalid_grant` without an auth
          // session means the auth session is used, expired or unknown, or the passkey is invalid.
          await this.#options.transaction.clear(storeOptions);
        }
      } else if (error instanceof OrganizationValidationError) {
        // Tokens were issued, but their organization does not match the one the flow started with.
        await this.#options.transaction.clear(storeOptions);
      }
    } catch {
      // Best effort. The exchange error is the one the caller has to handle, and an entry left behind
      // is deleted on the next attempt, which Auth0 answers with `invalid_grant`.
    }
  }

  async #persistSession(
    domain: string,
    audience: string | undefined,
    tokenEndpointResponse: TokenResponse,
    storeOptions?: TStoreOptions
  ): Promise<PasskeyGetTokenResult> {
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
