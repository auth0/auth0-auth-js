export { AuthClient } from './auth-client.js';
export * from './errors.js';
export * from './types.js';
export * from './mfa/index.js';
export * from './passkey/index.js';
export { PasswordlessClient } from './passwordless/passwordless-client.js';
export { PasswordlessStartError, PasswordlessVerifyError, PasswordlessChallengeError, PasswordlessDbGetTokenError } from './passwordless/errors.js';
export type { PasswordlessApiErrorResponse } from './passwordless/errors.js';
export type {
  PasswordlessClientOptions,
  SendEmailOptions,
  SendEmailCodeOptions,
  SendEmailLinkOptions,
  SendSmsOptions,
  ChallengeWithEmailOptions,
  ChallengeWithPhoneNumberOptions,
  PasswordlessChallenge,
  TokenByPasswordlessDbConnectionOptions,
} from './passwordless/types.js';
export type { TokenByMagicLinkCodeOptions } from './types.js';
export * from './database/index.js';
export * from './anonymous-session/index.js';
export { isFederatedDomain } from './domain-discovery.js';
export type { IsFederatedDomainOptions } from './domain-discovery.js';
