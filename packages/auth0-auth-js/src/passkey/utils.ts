import type {
  PasskeyClientOptions,
  PasskeySignupChallengeResponse,
  PasskeySignupChallengeApiResponse,
  PasskeyLoginChallengeResponse,
  PasskeyLoginChallengeApiResponse,
} from './types.js';

/**
 * Subset of {@link PasskeyClientOptions} carrying the client-authentication fields.
 * @internal
 */
export type ClientAuthOptions = Pick<PasskeyClientOptions, 'clientSecret' | 'useMtls'>;

/**
 * Builds the client-authentication fields for the `/passkey/register` and
 * `/passkey/challenge` request bodies.
 *
 * These endpoints accept `client_secret` as their only body-level credential, so a
 * `clientAssertionSigningKey` cannot be used with them. Under mTLS nothing is added,
 * because Auth0 rejects a request that also carries a credential in the body. Public
 * clients authenticate with `client_id` alone.
 *
 * @internal
 */
export function buildClientAuthBody(options: ClientAuthOptions): Record<string, string> {
  if (options.useMtls) {
    return {};
  }

  if (options.clientSecret) {
    return { client_secret: options.clientSecret };
  }

  // Public clients, and clients holding only a `clientAssertionSigningKey`, have no
  // credential to send here. The latter are rejected by Auth0, whose response the
  // caller surfaces unchanged.
  return {};
}

/**
 * Transforms API signup challenge response to SDK format.
 * @internal
 */
export function transformSignupChallengeResponse(
  api: PasskeySignupChallengeApiResponse
): PasskeySignupChallengeResponse {
  return {
    authSession: api.auth_session,
    authnParamsPublicKey: { ...api.authn_params_public_key },
  };
}

/**
 * Transforms API login challenge response to SDK format.
 * @internal
 */
export function transformLoginChallengeResponse(
  api: PasskeyLoginChallengeApiResponse
): PasskeyLoginChallengeResponse {
  return {
    authSession: api.auth_session,
    authnParamsPublicKey: { ...api.authn_params_public_key },
  };
}
