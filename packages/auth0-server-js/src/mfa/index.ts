export { ServerMfaClient } from './server-mfa-client.js';
export { MfaVerifyError } from './errors.js';
export type {
  MfaGrantType,
  MfaVerifyOtpOptions,
  MfaVerifyOobOptions,
  MfaVerifyRecoveryCodeOptions,
  MfaVerifyOptions,
  MfaVerifyResponse,
} from './types.js';

// Re-export MFA types and errors from auth0-auth-js for convenience
export type {
  AuthenticatorResponse,
  AuthenticatorType,
  OobChannel,
  ListAuthenticatorsOptions,
  DeleteAuthenticatorOptions,
  EnrollOtpOptions,
  EnrollOobOptions,
  EnrollEmailOptions,
  EnrollAuthenticatorOptions,
  OtpEnrollmentResponse,
  OobEnrollmentResponse,
  EnrollmentResponse,
  ChallengeOptions,
  ChallengeResponse,
} from '@auth0/auth0-auth-js';

export {
  MfaListAuthenticatorsError,
  MfaEnrollmentError,
  MfaDeleteAuthenticatorError,
  MfaChallengeError,
} from '@auth0/auth0-auth-js';
