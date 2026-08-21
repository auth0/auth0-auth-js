export { ServerAnonymousClient } from './server-anonymous-client.js';
export type { CreateAnonymousSessionOptions, GetAnonymousAccessTokenOptions } from './types.js';

// Re-export the anonymous session error from auth0-auth-js for convenience, so consumers
// can narrow thrown errors via `instanceof` and read `error.code` without importing
// auth0-auth-js directly. The anonymous session/state types are exported from `../types.js`.
//
// `AnonymousSessionErrorCode` is deliberately not re-exported. Its union ends in `string`, so
// it narrows nothing an `if (error.code === '...')` check would not already allow, and the
// codes worth handling are listed on the methods that can raise them.
export { AnonymousSessionError } from '@auth0/auth0-auth-js';
