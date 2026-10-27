import { OrganizationValidationError, PasskeyGetTokenError } from '@auth0/auth0-auth-js';
import { MissingRequiredArgumentError, MissingTransactionError } from '../errors.js';
import { applySessionExpiryAtLogin, updateStateDataAtLogin } from '../state/utils.js';
import { ensureOpenIdScope } from '../utils.js';
import {
  assertVerificationCodes,
  createPasskeyTransaction,
  getPasskeyTransactionExpiresAt,
  getTransactionAfterWrongCode,
  isSameChallenge,
  readSignedChallenge,
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
   * This method does not create a session; no state is persisted. Prefer
   * {@link ServerPasskeyClient.startSignup}, which keeps the `authSession` on the server.
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
   * This method does not create a session; no state is persisted. Prefer
   * {@link ServerPasskeyClient.startLogin}, which keeps the `authSession` on the server.
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
   * {@link ServerPasskeyClient.complete} instead. Prefer those methods: they keep the
   * `authSession` on the server and check the request before calling Auth0.
   *
   * For a signup where `register()` returned `verificationRequired`, pass the codes
   * the user entered in `verification`, for example `{ email: '123456' }`. Omit it
   * otherwise, including on login.
   *
   * On a wrong code this throws a `PasskeyGetTokenError` whose `isRetryable` is
   * `true`, whose `authSession` is set and whose `verificationRequired` lists the
   * identifiers still needing a code. Call again with the same `authSession` (Auth0
   * returns it unchanged as `error.authSession`) and `credential`, sending codes only
   * for those identifiers.
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
   * @throws {PasskeyGetTokenError} If there was an issue exchanging the credential for tokens. No session is persisted. When `isRetryable` is `true`, retry as described above. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`. When `cause.error` is `invalid_request`, for example for a missing code, the attempt usually stays open: fix the request and call again with the same `authSession`. Otherwise the attempt is usually over, so start again with `register()` or `challenge()`. A temporary failure, such as rate limiting (`statusCode` 429), can leave it open.
   * @throws {OrganizationValidationError} When `organization` is passed and the returned ID token's organization claim is missing or does not match. The error is thrown before the session is written, so no session is persisted in this case.
   * @throws {SessionExpiredError} When the ID token's `session_expiry` is already in the past at login (the session is born expired); nothing is persisted.
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
   * Starts a passkey signup for a new user, keeping the `authSession` in the Transaction Store.
   *
   * Requests a signup challenge like {@link ServerPasskeyClient.register}, then stores the
   * `authSession`, the challenge, the domain, the `realm` and `organization`, and `verificationRequired`
   * in the Transaction Store (with `CookieTransactionStore`, the encrypted `__a0_passkey_tx` cookie).
   * Only what the browser needs is returned: pass `authnParamsPublicKey` to
   * `navigator.credentials.create()`, and send the resulting credential to
   * {@link ServerPasskeyClient.complete}.
   *
   * When the connection requires the user's email address or phone number to be verified, the
   * result includes `verificationRequired` (for example `['email', 'phone']`), and Auth0 sends a
   * one-time code to each listed identifier during this call. Collect a code for each of them and
   * pass them to `complete()`. `deliveryMethod` (`'text'` or `'voice'`) chooses how the phone code is
   * delivered.
   *
   * Every call starts a new flow and, when verification is required, sends new codes. To recover
   * from a wrong code, call `complete()` again instead of this method. Do not rely only on Auth0's
   * limits: rate-limit the route that calls this method yourself, per IP address and per email
   * address or phone number.
   *
   * One passkey flow runs per browser at a time: starting a new signup or login replaces the
   * stored one. It expires together with the Auth0 auth session (60 seconds, or 15 minutes with
   * identifier verification). Without a `realm`, Auth0 uses the tenant's default directory.
   *
   * Client authentication works the same way as {@link ServerPasskeyClient.register}:
   * on a confidential client, only a `clientSecret` is accepted here.
   *
   * @param options User profile data, optional realm/organization, and an optional `deliveryMethod` for the phone code.
   * @param storeOptions Options passed to the Transaction Store, which this method writes to (a cookie-backed store needs what its `CookieHandler` uses to set the cookie), and used to resolve the domain in resolver mode. The store is written after Auth0 has sent the one-time codes, so a store error leaves the user with codes for a flow that was not stored.
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the signup challenge request. Use headers to forward the end user's IP address as auth0-forwarded-for.
   *
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge, for example when a one-time code could not be sent. `statusCode` holds the HTTP status, which is 429 when the request is rate limited. Nothing is stored in this case.
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
   * Starts a passkey login for an existing user, keeping the `authSession` in the Transaction Store.
   *
   * Requests a login challenge like {@link ServerPasskeyClient.challenge}, then stores the
   * `authSession`, the challenge, the domain, and the `realm` and `organization` in the
   * Transaction Store (with `CookieTransactionStore`, the encrypted `__a0_passkey_tx` cookie).
   * Only what the browser needs is returned: pass `authnParamsPublicKey` to
   * `navigator.credentials.get()`, and send the resulting credential to
   * {@link ServerPasskeyClient.complete}.
   *
   * One passkey flow runs per browser at a time: starting a new signup or login replaces the
   * stored one. It expires together with the Auth0 auth session (60 seconds). Without a `realm`,
   * Auth0 uses the tenant's default directory.
   *
   * Client authentication works the same way as {@link ServerPasskeyClient.register}:
   * on a confidential client, only a `clientSecret` is accepted here.
   *
   * @param options Optional realm/organization configuration.
   * @param storeOptions Options passed to the Transaction Store, which this method writes to (a cookie-backed store needs what its `CookieHandler` uses to set the cookie), and used to resolve the domain in resolver mode.
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
   * Before calling Auth0, `complete()` checks that the credential names the stored challenge (Auth0 verifies
   * its signature) and that every identifier in the stored `verificationRequired` has a one-time code that
   * is not blank.
   * After a wrong code, the stored list becomes the one Auth0 returns, so the next call needs codes only
   * for the identifiers that are still unverified.
   *
   * The stored transaction is deleted once Auth0 has used the auth session: on success (before the
   * session is written), on `mfa_required`, on an `invalid_grant` without an auth session (used,
   * expired or invalid passkey), and on an organization claim mismatch. It is kept on every other
   * failure, such as a wrong code (`error.isRetryable`), a rate limit (429), a server error or a
   * network error, so `complete()` can be called again with the same credential. If Auth0 had used the
   * auth session after all, that call fails with `invalid_grant` and deletes it.
   *
   * Deleting or updating the stored transaction after the exchange is best effort, and a Transaction
   * Store error there is not reported: after a success the login still succeeds, and after a failure
   * the original error is thrown. A custom store should log its own failures; see `TransactionStore`.
   *
   * @param options The serialized credential, a one-time code for every identifier that still needs one (see `verificationRequired`), and optional scope/audience. Set scope/audience in your server code, never from the request.
   * @param storeOptions Optional options used to pass to the Transaction and State Store.
   * @param requestOptions Optional per-request options (signal, headers, customFetch). Applied to the token exchange. Use headers to forward the end user's IP address as auth0-forwarded-for.
   *
   * @throws {MissingRequiredArgumentError} When `credential` is not provided, or its `response.clientDataJSON` is missing or cannot be read. Auth0 is not called, and the flow is kept.
   * @throws {MissingTransactionError} When no passkey signup or login is in progress, it has expired, or the credential was created for another challenge (for example in another tab, before a newer start replaced the transaction). Auth0 is not called; start a new flow.
   * @throws {PasskeyGetTokenError} When a one-time code is missing or blank, with `cause.error` set to `invalid_request` and the message naming the identifier; Auth0 is not called and the flow is kept, so collect the code and call `complete()` again. Also when there was an issue exchanging the credential for tokens: `isRetryable` is `true` for a wrong one-time code, so collect codes for the identifiers in `error.verificationRequired` and call `complete()` again with the same credential. When the cause is `mfa_required`, use `isMfaRequiredError(error)` to narrow the error and read `cause.mfa_token`. No session is persisted in these cases. Unlike with `getToken()`, the error never carries the `authSession`.
   * @throws {OrganizationValidationError} When the flow started with an `organization` and the returned ID token's organization claim is missing or does not match. No session is persisted in this case.
   * @throws {SessionExpiredError} When the ID token's `session_expiry` is already in the past at login (the session is born expired); nothing is persisted.
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

    // The challenge the authenticator signed. When it cannot be read, the challenge check below would
    // report a credential from another flow, and starting again would not help.
    const signedChallenge = readSignedChallenge(options.credential.response?.clientDataJSON);

    if (!signedChallenge) {
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
    if (!isSameChallenge(signedChallenge, transaction.challenge)) {
      throw new MissingTransactionError(
        'The passkey credential was not created for the passkey signup or login in progress. Call `passkey.startSignup()` or `passkey.startLogin()` to start again. ' +
          'If this happens on every attempt, check that the browser decodes the challenge in `authnParamsPublicKey` from base64url before it calls `navigator.credentials`.'
      );
    }

    // Every identifier that still needs a one-time code must have one. Without it, Auth0 could only answer
    // with an error, after the user has already gone through the passkey prompt.
    assertVerificationCodes(options.verification, transaction.verificationRequired ?? []);

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
      verificationRequired: 'verificationRequired' in response ? response.verificationRequired : undefined,
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
          // A wrong one-time code. Auth0 keeps the auth session and lists the identifiers that still need
          // a code, which the next attempt is checked against.
          const updated = getTransactionAfterWrongCode(transaction, error);

          if (updated) {
            await this.#options.transaction.write(updated, storeOptions);
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

    const stateData = applySessionExpiryAtLogin(
      updateStateDataAtLogin(audience ?? 'default', existingStateData, tokenEndpointResponse, { domain }),
      tokenEndpointResponse.claims
    );

    await this.#options.stateStore.set(this.#options.stateStoreIdentifier, stateData, true, storeOptions);

    // The visitor is authenticated now, so the anonymous session they may have had is over.
    await this.#options.onUserSessionEstablished?.(storeOptions);

    return {
      authorizationDetails: tokenEndpointResponse.authorizationDetails,
    };
  }
}
