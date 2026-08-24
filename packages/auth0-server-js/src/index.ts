export { ServerClient } from './server-client.js';
export { AbstractStateStore } from './store/abstract-state-store.js';
export { AbstractTransactionStore } from './store/abstract-transaction-store.js';
export type { TokenResponse, ActClaim } from '@auth0/auth0-auth-js';
export {
  TokenExchangeError,
  TokenRevocationError,
  MissingClientAuthError,
  OrganizationValidationError,
  PasswordlessStartError,
  PasswordlessVerifyError,
  isMfaRequiredError,
} from '@auth0/auth0-auth-js';

export type { CookieHandler, CookieSerializeOptions } from './store/cookie-handler.js';
export { CookieTransactionStore } from './store/cookie-transaction-store.js';

export { StatefulStateStore } from './store/stateful-state-store.js';
export type { StatefulStateStoreOptions } from './store/stateful-state-store.js';
export { StatelessStateStore } from './store/stateless-state-store.js';

export { AbstractAnonymousStore } from './store/abstract-anonymous-store.js';
export { StatelessAnonymousStore, DEFAULT_ANONYMOUS_SESSION_LIFETIME } from './store/stateless-anonymous-store.js';
export type { StatelessAnonymousStoreOptions, AnonymousCookieOptions } from './store/stateless-anonymous-store.js';

// Explicitly surface the STT error-code constant (also covered by `export * from './errors.js'`),
// for parity with the explicitly re-exported error classes above.
export { TokenExchangeErrorCode } from './errors.js';

export * from './errors.js';
export * from './types.js';
export * from './mfa/index.js';
export * from './passkey/index.js';
export * from './database/index.js';
export * from './anonymous/index.js';
