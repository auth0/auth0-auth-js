import type {
  Authenticator,
  AuthenticatorApiResponse,
  EnrollmentResponse,
  EnrollmentApiResponse,
  ChallengeResponse,
  ChallengeApiResponse,
} from './types.js';

/**
 * Transforms API authenticator response (snake_case) to SDK format (camelCase).
 * @internal
 */
export function transformAuthenticatorResponse(api: AuthenticatorApiResponse): Authenticator {
  return {
    id: api.id,
    authenticatorType: api.authenticator_type,
    active: api.active,
    name: api.name,
    createdAt: api.created_at,
    lastAuth: api.last_auth,
    type: api.type
  };
}

/**
 * Transforms API enrollment response (snake_case) to SDK format (camelCase).
 * @internal
 */
export function transformEnrollmentResponse(api: EnrollmentApiResponse): EnrollmentResponse {
  if (api.authenticator_type === 'otp') {
    return {
      authenticatorType: 'otp',
      secret: api.secret,
      barcodeUri: api.barcode_uri,
      recoveryCodes: api.recovery_codes,
      id: api.id,
    };
  }
  
  if (api.authenticator_type === 'oob') {
    return {
      authenticatorType: 'oob',
      oobChannel: api.oob_channel,
      oobCode: api.oob_code,
      bindingMethod: api.binding_method,
      id: api.id,
    };
  }
  
  // email
  return {
    authenticatorType: 'email',
    email: api.email,
    id: api.id,
  };
}

/**
 * Transforms API challenge response (snake_case) to SDK format (camelCase).
 * @internal
 */
export function transformChallengeResponse(api: ChallengeApiResponse): ChallengeResponse {
  return {
    challengeType: api.challenge_type,
    oobCode: api.oob_code,
    bindingMethod: api.binding_method,
  };
}
