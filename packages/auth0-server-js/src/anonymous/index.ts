export { ServerAnonymousClient } from './server-anonymous-client.js';
export type { CreateAnonymousSessionOptions, GetAnonymousAccessTokenOptions } from './types.js';

// Re-exported so consumers can narrow errors via `instanceof` without importing auth0-auth-js.
// `AnonymousSessionErrorCode` is omitted — its union ends in `string` and narrows nothing.
export { AnonymousSessionError } from '@auth0/auth0-auth-js';
