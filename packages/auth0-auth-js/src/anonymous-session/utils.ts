import { SignJWT, importPKCS8 } from 'jose';
import type { AnonymousSessionClientOptions } from './types.js';

const DEFAULT_CLIENT_ASSERTION_ALG = 'RS256';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const CLIENT_ASSERTION_EXPIRY_SECONDS = 120;

/**
 * Subset of {@link AnonymousSessionClientOptions} carrying the client-authentication fields.
 * @internal
 */
export type ClientAuthOptions = Pick<
  AnonymousSessionClientOptions,
  'clientSecret' | 'clientAssertionSigningKey' | 'clientAssertionSigningAlg'
>;

/**
 * Builds the client-authentication fields injected into the `/anonymous/token`
 * request body, matching node-auth0's `addClientAuthentication` (FR-1c).
 *
 * Resolution order: `private_key_jwt` → `client_secret_post` → public client
 * (no body auth).
 *
 * Unlike the passwordless variant, an empty object is returned for a public
 * client (no auth options configured): the anonymous token endpoint does not
 * require client authentication for public clients.
 *
 * @internal
 */
export async function buildClientAuthBody(
  options: ClientAuthOptions,
  clientId: string,
  domain: string
): Promise<Record<string, string>> {
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

  // Public client — no body-level authentication required.
  return {};
}
