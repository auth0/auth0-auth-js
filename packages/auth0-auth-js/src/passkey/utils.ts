import type {
  PasskeySignupChallengeResponse,
  PasskeySignupChallengeApiResponse,
  PasskeyLoginChallengeResponse,
  PasskeyLoginChallengeApiResponse,
} from './types.js';

/**
 * Transforms API signup challenge response to SDK format.
 * @internal
 */
export function transformSignupChallengeResponse(
  api: PasskeySignupChallengeApiResponse
): PasskeySignupChallengeResponse {
  return {
    authSession: api.auth_session,
    authnParamsPublicKey: {
      challenge: api.authn_params_public_key.challenge,
      rp: api.authn_params_public_key.rp,
      user: api.authn_params_public_key.user,
      pubKeyCredParams: api.authn_params_public_key.pubKeyCredParams,
      authenticatorSelection: api.authn_params_public_key.authenticatorSelection,
      timeout: api.authn_params_public_key.timeout,
    },
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
    authnParamsPublicKey: {
      challenge: api.authn_params_public_key.challenge,
      rpId: api.authn_params_public_key.rpId,
      timeout: api.authn_params_public_key.timeout,
      userVerification: api.authn_params_public_key.userVerification,
    },
  };
}
