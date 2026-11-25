export { ServerPasskeyClient } from './server-passkey-client.js';

// Re-export passkey error classes from auth0-auth-js for convenience, so consumers
// can narrow thrown errors via `instanceof` without importing auth0-auth-js directly.
// `OrganizationValidationError` is thrown by `getToken()` when an `organization` is
// passed and the returned ID token's organization claim is missing or mismatched.
// The passkey option/response types are re-exported from `../types.js`.
export {
  PasskeyRegisterError,
  PasskeyChallengeError,
  PasskeyGetTokenError,
  OrganizationValidationError,
} from '@auth0/auth0-auth-js';

// The types of the errors' `cause`, which holds the Auth0 error body (`error`, `error_description`).
// On a `PasskeyGetTokenError` it can also carry `auth_session` and `verification_required` (a wrong
// one-time code) or `mfa_token`. The HTTP status and headers are on the error itself, not on `cause`.
export type { PasskeyApiErrorResponse, PasskeyGetTokenApiErrorResponse } from '@auth0/auth0-auth-js';
