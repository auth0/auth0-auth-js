export { BrowserClient } from './browser-client.js';

// Store implementations
export { AbstractStateStore } from './store/abstract-state-store.js';
export { AbstractTransactionStore } from './store/abstract-transaction-store.js';
export { LocalStorageStateStore } from './store/local-storage-state-store.js';
export { LocalStorageTransactionStore } from './store/local-storage-transaction-store.js';
export { SessionStorageStateStore } from './store/session-storage-state-store.js';
export { SessionStorageTransactionStore } from './store/session-storage-transaction-store.js';
export { MemoryStateStore } from './store/memory-state-store.js';
export { MemoryTransactionStore } from './store/memory-transaction-store.js';

// Popup authentication
export { PopupHandler, sendPopupResponse } from './popup.js';

// DPoP support
export { Dpop } from './dpop/dpop.js';

// Authenticated fetcher
export { Fetcher } from './fetcher.js';

// Utility functions
export { decodeJWT } from './utils/decode-jwt.js';

// Errors and types
export * from './errors.js';
export * from './types.js';

// Re-export common types and classes from auth0-auth-js for convenience
export type {
  MfaClient,
  AuthenticatorResponse,
  EnrollmentResponse,
  ChallengeResponse,
} from '@auth0/auth0-auth-js';
