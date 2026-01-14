import type {
  AuthenticatorResponse,
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
export function transformAuthenticatorResponse(api: AuthenticatorApiResponse): AuthenticatorResponse {
  return {
    id: api.id,
    authenticatorType: api.authenticator_type,
    active: api.active,
    name: api.name,
    oobChannels: api.oob_channels,
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
  
  // OOB - covers SMS, Voice, Auth0, and Email channels
  if (api.authenticator_type === 'oob') {
    return {
      authenticatorType: 'oob',
      oobChannel: api.oob_channel,
      oobCode: api.oob_code,
      bindingMethod: api.binding_method,
      id: api.id,
    };
  }
  
  throw new Error(`Unexpected authenticator type: ${(api as { authenticator_type: string }).authenticator_type}`);
}

/**
 * Transforms API challenge response (snake_case) to SDK format (camelCase).
 * Only includes optional fields when they have values.
 * @internal
 */
export function transformChallengeResponse(api: ChallengeApiResponse): ChallengeResponse {
  const result: ChallengeResponse = {
    challengeType: api.challenge_type,
  };

  if (api.oob_code !== undefined) {
    result.oobCode = api.oob_code;
  }

  if (api.binding_method !== undefined) {
    result.bindingMethod = api.binding_method;
  }

  return result;
}
