import { SignJWT, importPKCS8 } from 'jose';
import { MissingClientAuthError } from '../errors.js';
import type {
  PasswordlessClientOptions,
  SendEmailOptions,
  SendSmsOptions,
  ChallengeWithEmailOptions,
  ChallengeWithPhoneNumberOptions,
} from './types.js';

const DEFAULT_CLIENT_ASSERTION_ALG = 'RS256';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const CLIENT_ASSERTION_EXPIRY_SECONDS = 120;

/**
 * Subset of {@link PasswordlessClientOptions} carrying the client-authentication fields.
 * @internal
 */
export type ClientAuthOptions = Pick<
  PasswordlessClientOptions,
  'clientSecret' | 'clientAssertionSigningKey' | 'clientAssertionSigningAlg' | 'useMtls'
>;

/**
 * Validates a phone number against a loose E.164 check (`+` followed by 1–15 digits).
 *
 * Auth0 performs full validation server-side; this is an early-fail guard only.
 * @internal
 */
export function isE164PhoneNumber(phoneNumber: string): boolean {
  return /^\+[1-9]\d{1,14}$/.test(phoneNumber);
}

/**
 * Builds the client-authentication fields injected into the `/passwordless/start`
 * request body, matching node-auth0's `addClientAuthentication` (FR-1c).
 *
 * Resolution order: mTLS (no body auth) → `private_key_jwt` → `client_secret_post`.
 *
 * @throws {MissingClientAuthError} When no client authentication method is configured.
 * @internal
 */
export async function buildClientAuthBody(
  options: ClientAuthOptions,
  clientId: string,
  domain: string
): Promise<Record<string, string>> {
  // mTLS: certificate is supplied by the custom fetch; no body-level auth.
  if (options.useMtls) {
    return {};
  }

  if (options.clientAssertionSigningKey) {
    const alg = options.clientAssertionSigningAlg ?? DEFAULT_CLIENT_ASSERTION_ALG;
    const privateKey =
      options.clientAssertionSigningKey instanceof CryptoKey
        ? options.clientAssertionSigningKey
        : await importPKCS8(options.clientAssertionSigningKey as string, alg);

    // Claims mirror node-auth0 client-authentication: iss/sub = clientId,
    // aud = `https://{domain}/` (trailing slash), short-lived, unique jti.
    const clientAssertion = await new SignJWT({})
      .setProtectedHeader({ alg })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience(`https://${domain}/`)
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .setExpirationTime(`${CLIENT_ASSERTION_EXPIRY_SECONDS}s`)
      .sign(privateKey);

    return {
      client_assertion: clientAssertion,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
    };
  }

  if (options.clientSecret) {
    return { client_secret: options.clientSecret };
  }

  throw new MissingClientAuthError();
}

/**
 * Transforms the public `sendEmail` options (camelCase) to the `/passwordless/start`
 * wire body. `authParams` is forwarded verbatim under its camelCase key (the sole
 * field that bypasses snake_case) to match node-auth0 / nextjs-auth0.
 * @internal
 */
export function transformSendEmailRequest(options: SendEmailOptions): Record<string, unknown> {
  const send = options.send ?? 'code';
  const wire: Record<string, unknown> = {
    email: options.email,
    connection: 'email',
    send,
  };

  if (send === 'link' && options.authParams) {
    wire.authParams = options.authParams;
  }

  return wire;
}

/**
 * Transforms the public `sendSms` options to the `/passwordless/start` wire body.
 * @internal
 */
export function transformSendSmsRequest(options: SendSmsOptions): Record<string, unknown> {
  return {
    phone_number: options.phoneNumber,
    connection: 'sms',
  };
}

/**
 * Transforms the public `ChallengeWithEmailOptions` (camelCase) to the `/otp/challenge`
 * wire body (snake_case).
 * @internal
 */
export function transformChallengeEmailRequest(
  options: ChallengeWithEmailOptions
): Record<string, unknown> {
  return {
    email: options.email,
    connection: options.connection,
    allow_signup: options.allowSignup ?? false,
  };
}

/**
 * Transforms the public `ChallengeWithPhoneNumberOptions` (camelCase) to the `/otp/challenge`
 * wire body (snake_case).
 * @internal
 */
export function transformChallengePhoneRequest(
  options: ChallengeWithPhoneNumberOptions
): Record<string, unknown> {
  return {
    phone_number: options.phoneNumber,
    connection: options.connection,
    delivery_method: options.deliveryMethod ?? 'text',
    allow_signup: options.allowSignup ?? false,
  };
}
