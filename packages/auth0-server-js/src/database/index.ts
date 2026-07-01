export { ServerDatabaseClient } from './server-database-client.js';

// Re-export database error classes from auth0-auth-js for convenience, so consumers
// can narrow thrown errors via `instanceof` without importing auth0-auth-js directly.
// The database option/result types are re-exported from `../types.js`.
export { SignUpError, ChangePasswordError } from '@auth0/auth0-auth-js';
