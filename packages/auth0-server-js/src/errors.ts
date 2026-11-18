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
 *
 * @category Errors
 */
export const TokenExchangeErrorCode = {
  ACTOR_UNAVAILABLE: 'actor_unavailable',
  SETACTOR_REQUIRED: 'setactor_required',
  SESSION_TRANSFER_DISABLED: 'session_transfer_disabled',
} as const;

/** @category Errors */
export type TokenExchangeErrorCode = (typeof TokenExchangeErrorCode)[keyof typeof TokenExchangeErrorCode];

/**
 * Error thrown when there is no transaction available.
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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
 *
 * @category Errors
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

/**
 * The claims that a Poppy Session needs: the members of the `act` claim, the `sub` of the token and its `exp`.
 * {@link InvalidPoppySessionError} names the one that is not well formed.
 *
 * @beta
 * @category Errors
 */
export type PoppySessionMember =
  | 'act.sub'
  | 'act.poppy_sid'
  | 'act.poppy_user_id'
  | 'act.poppy_agent_id'
  | 'sub'
  | 'exp';

/**
 * Error thrown when an ID token holds a Poppy Session (its `act` claim has a `poppy_sid`) that is not well formed.
 *
 * The message names the claim that is invalid. It never shows the value, which comes from a token.
 *
 * No `ServerClient` method throws it: a login with such a token is refused with a {@link PoppyError}
 * (`invalid_poppy_agent` for a signed-in agent, `invalid_poppy_guest` for a guest).
 *
 * @beta
 * @category Errors
 */
export class InvalidPoppySessionError extends Error {
  public code: string = 'invalid_poppy_session';

  /** The claim that is not valid. It is a name, never a value of the token. */
  public member: PoppySessionMember;

  constructor(member: PoppySessionMember) {
    super(`The ID token does not hold a well-formed Poppy Session: ${member} is invalid.`);
    this.name = 'InvalidPoppySessionError';
    this.member = member;
  }
}

/**
 * The codes of a {@link PoppyError}. They are the `code` of the error, and an app can answer each one in its own way.
 *
 * - `invalid_poppy_guest`: the ID token looks like the login of a Poppy guest (it has the `anon_poppy@` `sub` or the
 *   anonymous `sub_profile`) but is not a valid one. The SDK refuses it, so that an anonymous subject never becomes a
 *   user session. `error.reason` names the check that failed.
 * - `invalid_poppy_agent`: the ID token holds a Poppy Session in its `act` claim (it has a `poppy_sid`) that is not
 *   well formed, or the token of a signed-in agent has no valid `sub` or `exp`. The SDK refuses it, so that a session
 *   is never written without the deadline of an agent. `error.reason` names the claim that failed.
 * - `poppy_guest_not_supported`: a guest login came through a method that is not the redirect callback
 *   (`completeInteractiveLogin()`). Guests come from a browser join, so they complete only there.
 * - `poppy_sign_in_required`: a login was refused because an agent's guest is in this browser. Only a signed-in agent,
 *   a new guest join, or the same guest coming back after its access token has expired (a renewal) may replace the
 *   guest. A person's login, the same guest coming back while its token is valid, and a silent login that gives one of
 *   those are refused. Logging out ends the guest, and then the person can sign in.
 *
 * @beta
 * @category Errors
 */
export const PoppyErrorCode = {
  INVALID_GUEST: 'invalid_poppy_guest',
  INVALID_AGENT: 'invalid_poppy_agent',
  GUEST_NOT_SUPPORTED: 'poppy_guest_not_supported',
  SIGN_IN_REQUIRED: 'poppy_sign_in_required',
} as const;

/**
 * The `code` of a {@link PoppyError}: `invalid_poppy_guest`, `invalid_poppy_agent`, `poppy_guest_not_supported` or
 * `poppy_sign_in_required`.
 *
 * @beta
 * @category Errors
 */
export type PoppyErrorCode = (typeof PoppyErrorCode)[keyof typeof PoppyErrorCode];

const POPPY_ERROR_MESSAGES: Record<PoppyErrorCode, string> = {
  [PoppyErrorCode.INVALID_GUEST]:
    'The ID token looks like the login of a Poppy guest but is not a valid one, so it is neither a guest nor a user.',
  [PoppyErrorCode.INVALID_AGENT]:
    'The ID token holds a Poppy Session that is not well formed, so it is neither a signed-in agent nor a user.',
  [PoppyErrorCode.GUEST_NOT_SUPPORTED]:
    'A Poppy guest login can only complete through the redirect callback, not through another login method.',
  [PoppyErrorCode.SIGN_IN_REQUIRED]:
    "An agent's guest is in this browser, so only a signed-in agent, a new guest join, or the same guest renewing an expired access token can replace it. Log out to sign in as a person.",
};

/**
 * Error thrown with the `poppy` option when a login is refused because of Poppy. Nothing is stored when it is thrown.
 * Check `error.code` against {@link PoppyErrorCode}. An app usually answers with a 403.
 *
 * The message is a fixed text for the code, and it is safe to show. `reason` is for logs only.
 *
 * @beta
 * @category Errors
 */
export class PoppyError extends Error {
  public code: PoppyErrorCode;

  /**
   * Why the login was refused, for `invalid_poppy_guest` and `invalid_poppy_agent`: the check that failed. It names
   * claims and never shows their values, except `sub_profile`, which is a short label. It is for logs and is never part
   * of the message.
   */
  public reason?: string;

  constructor(code: PoppyErrorCode, reason?: string) {
    super(POPPY_ERROR_MESSAGES[code]);
    this.name = 'PoppyError';
    this.code = code;
    this.reason = reason;
  }
}
