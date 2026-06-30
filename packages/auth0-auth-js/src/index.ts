export { AuthClient } from './auth-client.js';
export * from './errors.js';
export * from './types.js';
export * from './mfa/index.js';
export * from './passkey/index.js';
export { PasswordlessClient } from './passwordless/passwordless-client.js';
export { PasswordlessStartError, PasswordlessVerifyError } from './passwordless/errors.js';
export type { PasswordlessApiErrorResponse } from './passwordless/errors.js';
export type {
  PasswordlessClientOptions,
  SendEmailOptions,
  SendEmailCodeOptions,
  SendEmailLinkOptions,
  SendSmsOptions,
} from './passwordless/types.js';
export * from './database/index.js';
