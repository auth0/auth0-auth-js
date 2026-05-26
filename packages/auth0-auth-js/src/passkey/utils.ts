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
