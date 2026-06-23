export { ServerPasskeyClient } from './server-passkey-client.js';

// Re-export passkey error classes from auth0-auth-js for convenience, so consumers
// can narrow thrown errors via `instanceof` without importing auth0-auth-js directly.
// The passkey option/response types are re-exported from `../types.js`.
export { PasskeyRegisterError, PasskeyChallengeError, PasskeyGetTokenError } from '@auth0/auth0-auth-js';
