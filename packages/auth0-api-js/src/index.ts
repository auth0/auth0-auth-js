export { ApiClient } from './api-client.js';
export * from './protected-resource-metadata.js';
export * from './errors.js';
export * from './types.js';
export { getToken } from './token.js';

// Re-export shared errors from auth0-auth-js for convenience
export {
  MissingClientAuthError,
  TokenExchangeError,
} from '@auth0/auth0-auth-js';
