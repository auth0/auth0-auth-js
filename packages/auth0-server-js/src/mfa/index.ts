export { ServerMfaClient } from './server-mfa-client.js';
export type { MfaVerifyResponse } from './types.js';
export type {
  MfaFactorType,
  MfaVerifyOtpOptions,
  MfaVerifyOobOptions,
  MfaVerifyRecoveryCodeOptions,
  MfaVerifyOptions,
} from '@auth0/auth0-auth-js';

// Re-export MFA types and errors from auth0-auth-js for convenience
export type {
  AuthenticatorResponse,
  AuthenticatorType,
  OobChannel,
  ListAuthenticatorsOptions,
  EnrollOtpOptions,
  EnrollOobOptions,
  EnrollEmailOptions,
  EnrollAuthenticatorOptions,
  OtpEnrollmentResponse,
  OobEnrollmentResponse,
  EnrollmentResponse,
  ChallengeOptions,
  ChallengeResponse,
  MfaRequirements,
  OAuth2Error,
} from '@auth0/auth0-auth-js';

export {
  MfaListAuthenticatorsError,
  MfaEnrollmentError,
  MfaChallengeError,
  MfaVerifyError,
  isMfaRequiredError,
} from '@auth0/auth0-auth-js';
