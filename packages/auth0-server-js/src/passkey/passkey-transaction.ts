import { base64url } from 'jose';
import { PasskeyGetTokenError } from '@auth0/auth0-auth-js';
import type { PasskeyCredentialResponse, TransactionData } from '../types.js';
import type { TransactionSlotEntry } from '../store/transaction-slot.js';

/**
 * @internal
 * The `kind` of the transaction-store entry written by `passkey.startSignup()` and `passkey.startLogin()`.
 */
export const PASSKEY_TRANSACTION_KIND = 'passkey';

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
  kind: typeof PASSKEY_TRANSACTION_KIND;
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
}

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

const isOptionalString = (value: unknown) => value === undefined || typeof value === 'string';

/**
 * @internal
 */
export const isPasskeyTransactionData = (data: TransactionData): data is PasskeyTransactionData =>
  data.kind === PASSKEY_TRANSACTION_KIND &&
  isNonEmptyString(data.authSession) &&
  isNonEmptyString(data.challenge) &&
  isNonEmptyString(data.domain) &&
  typeof data.expiresAt === 'number' &&
  Number.isFinite(data.expiresAt) &&
  isOptionalString(data.realm) &&
  isOptionalString(data.organization);

/**
 * @internal
 * Builds a passkey transaction with only the known fields, leaving out a `realm` or `organization`
 * that was not sent to Auth0.
 */
export const createPasskeyTransaction = (
  fields: Pick<PasskeyTransactionData, 'authSession' | 'challenge' | 'domain' | 'expiresAt' | 'realm' | 'organization'>
): PasskeyTransactionData => ({
  kind: PASSKEY_TRANSACTION_KIND,
  authSession: fields.authSession,
  challenge: fields.challenge,
  domain: fields.domain,
  expiresAt: fields.expiresAt,
  ...(fields.realm && { realm: fields.realm }),
  ...(fields.organization && { organization: fields.organization }),
});

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
 * Reads the challenge the authenticator signed from the credential's `clientDataJSON`.
 * Returns `undefined` when it cannot be read.
 */
const readSignedChallenge = (credential: PasskeyCredentialResponse): string | undefined => {
  const clientDataJSON: unknown = credential?.response?.clientDataJSON;

  if (!isNonEmptyString(clientDataJSON)) {
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
 * Removes the auth session from an error thrown by `passkey.complete()`. The transaction already keeps
 * it, and an error is easily logged or sent to the browser by mistake. `isRetryable` and the other
 * fields are unaffected.
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
 * Whether the credential was created for the given challenge. Both are base64url in practice; they are
 * normalized first, so padding or the base64 alphabet cannot cause a false mismatch.
 */
export const isCredentialForChallenge = (credential: PasskeyCredentialResponse, challenge: string): boolean => {
  const signedChallenge = readSignedChallenge(credential);

  return signedChallenge !== undefined && toBase64url(signedChallenge) === toBase64url(challenge);
};
