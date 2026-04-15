import type {
  AuthenticatorResponse,
  AuthenticatorApiResponse,
  ChallengeType,
  AuthenticatorType,
  OobChannel,
  EnrollmentResponse,
  EnrollmentApiResponse,
  ChallengeResponse,
  ChallengeApiResponse,
} from './types.js';

/**
 * Derives a challenge type from the authenticator type and OOB channel.
 *
 * The Auth0 API returns `authenticator_type` and `oob_channel` separately.
 * This function maps them to a single challenge type value.
 * @internal
 */
export function deriveChallengeType(authenticatorType: AuthenticatorType, oobChannel?: OobChannel): ChallengeType | undefined {
  if (authenticatorType === 'otp') return 'otp';
  if (authenticatorType === 'recovery-code') return 'recovery-code';
  if (authenticatorType === 'oob') {
    if (oobChannel === 'sms' || oobChannel === 'voice') return 'phone';
    if (oobChannel === 'auth0') return 'push-notification';
    if (oobChannel === 'email') return 'email';
  }
  return undefined;
}

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
    type: deriveChallengeType(api.authenticator_type, api.oob_channel),
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
      barcodeUri: api.barcode_uri,
      recoveryCodes: api.recovery_codes,
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
