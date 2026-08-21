/**
 * Codes carried on the `code` field of a `TokenExchangeError` raised by the Session
 * Transfer Token (STT) flow. These are specific to Custom Token Exchange Impersonation
 * via Session Transfer:
 *
 * - `actor_unavailable` — raised client-side, before any network call, when a Session
 *   Transfer Token is requested but no actor could be resolved (no explicit actor and
 *   no usable session ID token).
 * - `setactor_required` — the server rejected the exchange because the Action did not
 *   call `setActor` (an actor is mandatory for a Session Transfer Token).
 * - `session_transfer_disabled` — the server rejected the exchange because the tenant
 *   feature flag is off.
 *
 * Only `actor_unavailable` is raised by the SDK itself. `setactor_required` and
 * `session_transfer_disabled` are surfaced from the raw server response via the
 * error's `cause.error` / `cause.error_description`; they are defined here as named
 * constants for documentation and for the day the platform returns a machine-readable
 * code.
 */
export const TokenExchangeErrorCode = {
  ACTOR_UNAVAILABLE: 'actor_unavailable',
  SETACTOR_REQUIRED: 'setactor_required',
  SESSION_TRANSFER_DISABLED: 'session_transfer_disabled',
} as const;

export type TokenExchangeErrorCode = (typeof TokenExchangeErrorCode)[keyof typeof TokenExchangeErrorCode];

/**
 * Error thrown when there is no transaction available.
 */
export class MissingTransactionError extends Error {
  public code: string = 'missing_transaction_error';

  constructor(message?: string) {
    super(message ?? 'The transaction is missing.');
    this.name = 'MissingTransactionError';
  }
}


/**
 * Error thrown when backchannel logout fails.
 */
export class BackchannelLogoutError extends Error {
  public code: string = 'backchannel_logout_error';

  constructor(message: string) {
    super(message);
    this.name = 'BackchannelLogoutError';
  }
}

/**
 * Error thrown when starting the user-linking failed.
 */
export class StartLinkUserError extends Error {
  public code: string = 'start_link_user_error';

  constructor(message: string) {
    super(message);
    this.name = 'StartLinkUserError';
  }
}

/**
 * Error thrown when a required argument is missing.
 */
export class MissingRequiredArgumentError extends Error {
  public code: string = 'missing_required_argument_error';

  constructor(argument: string) {
    super(`The argument '${argument}' is required but was not provided.`);
    this.name = 'MissingRequiredArgumentError';
  }
}

/**
 * Error thrown when a session is missing.
 */
export class MissingSessionError extends Error {
  public code: string = 'missing_session_error';

  constructor(message: string) {
    super(message);
    this.name = 'MissingSessionError';
  }
}

/**
 * Error thrown when a configuration is invalid.
 */
export class InvalidConfigurationError extends Error {
  public code: string = 'invalid_configuration_error';

  constructor(message: string) {
    super(message);
    this.name = 'InvalidConfigurationError';
  }
}

/**
 * Error thrown when the issuer validation fails.
 */
export class IssuerValidationError extends Error {
  public code: string = 'issuer_validation_error';

  constructor(message: string) {
    super(message);
    this.name = 'IssuerValidationError';
  }
}

/**
 * Error thrown when an anonymous session is required but none is stored for this visitor.
 *
 * Anonymous sessions are never created implicitly. Call
 * `serverClient.anonymous.createSession()` first, and use
 * `serverClient.anonymous.getSession()` to check whether a visitor already has one.
 */
export class MissingAnonymousSessionError extends Error {
  public code: string = 'missing_anonymous_session_error';

  constructor(message?: string) {
    super(message ?? 'There is no anonymous session. Call `anonymous.createSession()` first.');
    this.name = 'MissingAnonymousSessionError';
  }
}

/**
 * Error thrown when the anonymous session has expired or was rejected by Auth0, so no new
 * anonymous access token can be minted for it.
 *
 * The stored anonymous session is deleted before this is thrown. Call
 * `serverClient.anonymous.createSession()` to start a new one. Any metadata attached to
 * the previous anonymous identity is gone: metadata is set once, at creation.
 *
 * Recovering from this is not free. `@auth0/auth0-auth-js` answers an expired session token
 * by creating a replacement anonymous identity rather than reporting the expiry, so by the
 * time this error is raised Auth0 has already minted an identity the SDK deliberately
 * discards (storing it would move the visitor onto an identity they never asked for, without
 * their metadata). The `createSession()` that recovers is therefore a second call to Auth0,
 * and under concurrency every in-flight request pays it. Handle this once, on a path the
 * visitor actually needs a token on, rather than in a retry loop.
 */
export class AnonymousSessionExpiredError extends Error {
  public code: string = 'anonymous_session_expired';

  constructor(message?: string) {
    super(
      message ??
        'The anonymous session has expired or is no longer valid. Call `anonymous.createSession()` to start a new one.'
    );
    this.name = 'AnonymousSessionExpiredError';
  }
}

/**
 * Error thrown when the session has passed its upstream IdP-asserted
 * `session_expiry` ceiling (IPSIE SL1). The user must re-authenticate.
 */
export class SessionExpiredError extends Error {
  public code: string = 'session_expired';

  constructor(message?: string) {
    super(
      message ??
        'The session has expired because the upstream identity provider session ceiling was reached. The user needs to re-authenticate.'
    );
    this.name = 'SessionExpiredError';
  }
}
