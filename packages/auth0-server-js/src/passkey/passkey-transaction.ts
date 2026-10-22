import { base64url } from 'jose';
import { PasskeyGetTokenError } from '@auth0/auth0-auth-js';
import type { TransactionData } from '../types.js';
import type { TransactionSlotEntry } from '../store/transaction-slot.js';

/**
 * The lifetime used when Auth0 returns no usable `timeout`, and the longest a passkey transaction is
 * ever kept. Matches the lifetime of the redirect-login transaction cookie.
 */
const MAX_PASSKEY_TRANSACTION_LIFETIME = 60 * 60;

/**
 * @internal
 * What `passkey.startSignup()` and `passkey.startLogin()` keep in the transaction store for `passkey.complete()`.
 */
export interface PasskeyTransactionData extends TransactionSlotEntry {
  /**
   * The Auth0 auth session. It never leaves the server.
   */
  authSession: string;
  /**
   * The WebAuthn challenge Auth0 issued together with the auth session.
   */
  challenge: string;
  /**
   * The Auth0 domain that issued the auth session.
   */
  domain: string;
  realm?: string;
  organization?: string;
  /**
   * The identifiers that still need a one-time code: the list from the signup challenge, replaced by the
   * shorter list Auth0 returns after a wrong code. Every `complete()` call needs a code for each of them.
   */
  verificationRequired?: string[];
}

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

const isOptionalString = (value: unknown) => value === undefined || typeof value === 'string';

const isOptionalStringArray = (value: unknown) =>
  value === undefined || (Array.isArray(value) && value.every((item) => typeof item === 'string'));

/**
 * @internal
 */
export const isPasskeyTransactionData = (data: TransactionData): data is PasskeyTransactionData =>
  isNonEmptyString(data.authSession) &&
  isNonEmptyString(data.challenge) &&
  isNonEmptyString(data.domain) &&
  typeof data.expiresAt === 'number' &&
  Number.isFinite(data.expiresAt) &&
  isOptionalString(data.realm) &&
  isOptionalString(data.organization) &&
  isOptionalStringArray(data.verificationRequired);

/**
 * @internal
 * Builds a passkey transaction with only the known fields, leaving out a `realm` or `organization`
 * that was not sent to Auth0, and an empty `verificationRequired`.
 */
export const createPasskeyTransaction = (
  fields: Pick<
    PasskeyTransactionData,
    'authSession' | 'challenge' | 'domain' | 'expiresAt' | 'realm' | 'organization' | 'verificationRequired'
  >
): PasskeyTransactionData => ({
  authSession: fields.authSession,
  challenge: fields.challenge,
  domain: fields.domain,
  expiresAt: fields.expiresAt,
  ...(fields.realm && { realm: fields.realm }),
  ...(fields.organization && { organization: fields.organization }),
  ...(fields.verificationRequired?.length ? { verificationRequired: fields.verificationRequired } : {}),
});

const verificationCodeError = (message: string) =>
  new PasskeyGetTokenError(message, { error: 'invalid_request', error_description: message });

/**
 * @internal
 * Checks that every identifier in `verificationRequired` has a one-time code, in the order of the list,
 * and throws for the first one that has none. A code that is empty or only whitespace counts as empty. A
 * value that is not a string counts as missing when it is falsy, because it is not sent. Codes that pass
 * are sent as they are, and codes for identifiers that are not listed are not checked.
 *
 * The error has the shape of the `invalid_request` Auth0 returns for a missing code: `isRetryable` is
 * `false` and there is no `authSession`.
 *
 * @throws {PasskeyGetTokenError}
 */
export const assertVerificationCodes = (verification: unknown, verificationRequired: string[]): void => {
  for (const identifier of verificationRequired) {
    const code: unknown = (verification as Record<string, unknown> | null | undefined)?.[identifier];

    if (typeof code === 'string' && !code.trim()) {
      throw verificationCodeError(`"verification.${identifier}" is not allowed to be empty`);
    }

    // A falsy value is left out of the request, so Auth0 would see no code at all.
    if (typeof code !== 'string' && !code) {
      throw verificationCodeError(`Missing required parameter: verification.${identifier}`);
    }
  }
};

const isSameList = (a: string[] = [], b: string[] = []) =>
  a.length === b.length && a.every((item, index) => item === b[index]);

/**
 * @internal
 * The transaction to keep after Auth0 rejected a one-time code, or `undefined` when nothing changed.
 * Auth0 keeps the auth session, returns it, and lists the identifiers that still need a code, so a retry
 * needs codes for exactly those. When the error lists none, the stored list stays.
 */
export const getTransactionAfterWrongCode = (
  transaction: PasskeyTransactionData,
  error: PasskeyGetTokenError
): PasskeyTransactionData | undefined => {
  const authSession = error.authSession || transaction.authSession;
  const verificationRequired = error.verificationRequired?.length
    ? error.verificationRequired
    : transaction.verificationRequired;

  if (authSession === transaction.authSession && isSameList(verificationRequired, transaction.verificationRequired)) {
    return;
  }

  return createPasskeyTransaction({ ...transaction, authSession, verificationRequired });
};

/**
 * @internal
 * Computes when a passkey transaction stops being usable, from the WebAuthn `timeout` (milliseconds)
 * that Auth0 returns with the challenge. Auth0 sets it to the lifetime of the auth session: 60 seconds,
 * or 15 minutes for a signup with identifier verification.
 */
export const getPasskeyTransactionExpiresAt = (timeout: unknown): number => {
  const lifetime =
    typeof timeout === 'number' && Number.isFinite(timeout) && timeout > 0
      ? Math.min(Math.ceil(timeout / 1000), MAX_PASSKEY_TRANSACTION_LIFETIME)
      : MAX_PASSKEY_TRANSACTION_LIFETIME;

  return Math.floor(Date.now() / 1000 + lifetime);
};

/**
 * Normalizes a base64 or base64url value to base64url without padding.
 *
 * The padding pattern is bounded on purpose: base64 has at most two padding characters, and an
 * unbounded `=+$` backtracks quadratically on a long run of `=` that is not at the end.
 */
const toBase64url = (value: string) => value.replace(/\+/g, '-').replace(/\//g, '_').replace(/={1,2}$/, '');

/**
 * @internal
 * Reads the challenge the authenticator signed from a credential's `clientDataJSON`.
 * Returns `undefined` when it cannot be read.
 */
export const readSignedChallenge = (clientDataJSON: unknown): string | undefined => {
  if (typeof clientDataJSON !== 'string') {
    return;
  }

  try {
    const clientData: unknown = JSON.parse(new TextDecoder().decode(base64url.decode(toBase64url(clientDataJSON))));
    const challenge = (clientData as { challenge?: unknown } | null)?.challenge;

    return isNonEmptyString(challenge) ? challenge : undefined;
  } catch {
    return;
  }
};

/**
 * @internal
 * Removes the auth session from an error thrown by `passkey.complete()`. With these methods the auth
 * session stays inside the SDK: the transaction keeps it and the application never needs it, so errors
 * do not hand it out either. `isRetryable` and the other fields are unaffected.
 *
 * Never throws, so it can never replace the real error: `Reflect.deleteProperty` reports a field it
 * cannot delete instead of throwing, and the try/catch covers anything more unusual.
 */
export const redactAuthSession = (error: unknown): void => {
  if (!(error instanceof PasskeyGetTokenError)) {
    return;
  }

  try {
    Reflect.deleteProperty(error, 'authSession');

    if (error.cause) {
      Reflect.deleteProperty(error.cause, 'auth_session');
    }
  } catch {
    // see above
  }
};

/**
 * @internal
 * Whether two challenges are the same. Both are base64url in practice; they are normalized first, so
 * padding or the base64 alphabet cannot cause a false mismatch.
 */
export const isSameChallenge = (signedChallenge: string, challenge: string): boolean =>
  toBase64url(signedChallenge) === toBase64url(challenge);
