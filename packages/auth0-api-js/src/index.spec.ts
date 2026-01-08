import { describe, expect, test } from 'vitest';

import * as pkg from './index.js';
import { ApiClient as DirectApiClient } from './api-client.js';
import { getToken as directGetToken } from './token.js';
import {
  MissingClientAuthError as BaseMissingClientAuthError,
  TokenExchangeError as BaseTokenExchangeError,
} from '@auth0/auth0-auth-js';
import {
  InvalidRequestError,
  MissingTransactionError,
  VerifyAccessTokenError,
} from './errors.js';
import { ProtectedResourceMetadataBuilder, BearerMethod } from './protected-resource-metadata.js';

describe('index exports', () => {
  test('re-exports ApiClient', () => {
    expect(pkg.ApiClient).toBe(DirectApiClient);
  });

  test('re-exports getToken', () => {
    expect(pkg.getToken).toBe(directGetToken);
    expect(typeof pkg.getToken).toBe('function');
  });

  test('re-exports errors from this package', () => {
    expect(pkg.InvalidRequestError).toBe(InvalidRequestError);
    expect(pkg.MissingTransactionError).toBe(MissingTransactionError);
    expect(pkg.VerifyAccessTokenError).toBe(VerifyAccessTokenError);
  });

  test('MissingTransactionError uses default message', () => {
    const err = new MissingTransactionError();
    expect(err.message).toBe('The transaction is missing.');
    expect(err.code).toBe('missing_transaction_error');
  });

  test('re-exports auth0-auth-js errors', () => {
    expect(pkg.MissingClientAuthError).toBe(BaseMissingClientAuthError);
    expect(pkg.TokenExchangeError).toBe(BaseTokenExchangeError);
  });

  test('re-exports protected resource metadata helpers', () => {
    expect(pkg.ProtectedResourceMetadataBuilder).toBe(ProtectedResourceMetadataBuilder);
    expect(pkg.BearerMethod).toBe(BearerMethod);
  });
});
