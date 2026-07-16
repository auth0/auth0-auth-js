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
