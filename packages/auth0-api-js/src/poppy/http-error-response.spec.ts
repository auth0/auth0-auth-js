import { describe, expect, test } from 'vitest';

import {
  AuthError,
  InvalidConfigurationError,
  InvalidDpopProofError,
  InvalidRequestError,
  MissingOrganizationError,
  MissingRequiredArgumentError,
  OrganizationNotAllowedError,
  VerifyAccessTokenError,
} from '../errors.js';
import { POPPY_UNAVAILABLE_MESSAGE, SESSION_ENDED_MESSAGE } from './constants.js';
import { InvalidSessionError, PoppyUnavailableError, SessionEndedError, SignInRequiredError } from './errors.js';
import { toHttpErrorResponse, type HttpErrorResponse } from './http-error-response.js';

const INVALID_TOKEN_CHALLENGES = {
  'www-authenticate': ['Bearer realm="api", error="invalid_token"', 'DPoP error="invalid_token", algs="ES256"'],
};
const BEARER_CHALLENGE = { 'www-authenticate': 'Bearer realm="api"' };

function responseFor(error: unknown): HttpErrorResponse {
  const response = toHttpErrorResponse(error);
  if (!response) {
    throw new Error('Expected a response.');
  }
  return response;
}

describe('toHttpErrorResponse', () => {
  const signInRequired = new SignInRequiredError({ scope: 'orders:write' });

  test.each<[string, unknown, HttpErrorResponse]>([
    [
      'InvalidSessionError',
      new InvalidSessionError('claim_mismatch', 'x'),
      { status: 400, headers: {}, body: { error: 'invalid_session', error_description: 'x' } },
    ],
    [
      'SessionEndedError',
      new SessionEndedError(),
      { status: 400, headers: {}, body: { error: 'session_ended', error_description: SESSION_ENDED_MESSAGE } },
    ],
    [
      'SignInRequiredError',
      signInRequired,
      {
        status: 401,
        headers: {
          'www-authenticate': ['Bearer realm="api", scope="orders:write"', 'DPoP scope="orders:write", algs="ES256"'],
        },
        body: undefined,
      },
    ],
    [
      'PoppyUnavailableError',
      new PoppyUnavailableError(),
      {
        status: 503,
        headers: { 'retry-after': '30' },
        body: { error: 'temporarily_unavailable', error_description: POPPY_UNAVAILABLE_MESSAGE },
      },
    ],
    [
      'VerifyAccessTokenError with headers',
      new VerifyAccessTokenError('The access token is not valid.', INVALID_TOKEN_CHALLENGES),
      { status: 401, headers: INVALID_TOKEN_CHALLENGES, body: undefined },
    ],
    [
      'VerifyAccessTokenError without headers',
      new VerifyAccessTokenError('The access token is not valid.'),
      { status: 401, headers: {}, body: undefined },
    ],
    [
      'MissingOrganizationError',
      new MissingOrganizationError(undefined, INVALID_TOKEN_CHALLENGES),
      { status: 401, headers: INVALID_TOKEN_CHALLENGES, body: undefined },
    ],
    [
      'OrganizationNotAllowedError',
      new OrganizationNotAllowedError(undefined, INVALID_TOKEN_CHALLENGES),
      { status: 401, headers: INVALID_TOKEN_CHALLENGES, body: undefined },
    ],
    [
      'InvalidRequestError',
      new InvalidRequestError('No token.', BEARER_CHALLENGE),
      { status: 400, headers: BEARER_CHALLENGE, body: undefined },
    ],
    [
      'InvalidDpopProofError',
      new InvalidDpopProofError('Bad proof.', { 'www-authenticate': 'DPoP error="invalid_dpop_proof", algs="ES256"' }),
      {
        status: 400,
        headers: { 'www-authenticate': 'DPoP error="invalid_dpop_proof", algs="ES256"' },
        body: undefined,
      },
    ],
    [
      'AuthError with a status code and another code',
      new AuthError('A teapot.', 'teapot', 418, { 'x-tea': 'oolong' }),
      { status: 418, headers: { 'x-tea': 'oolong' }, body: undefined },
    ],
  ])('%s | maps to its HTTP response', (_label, error, expected) => {
    expect(toHttpErrorResponse(error)).toEqual(expected);
  });

  test.each<[string, unknown]>([
    ['an AuthError without a status code', new AuthError('No status.', 'some_code')],
    ['a plain Error', new Error('boom')],
    ['an Error with a status code of its own', Object.assign(new Error('boom'), { statusCode: 400 })],
    ['an InvalidConfigurationError', new InvalidConfigurationError('Invalid poppy configuration: bad.')],
    ['a MissingRequiredArgumentError', new MissingRequiredArgumentError('audience')],
    ['an object shaped like an AuthError', { code: 'invalid_session', statusCode: 400, message: 'x', headers: {} }],
    ['a string', 'x'],
    ['null', null],
    ['undefined', undefined],
  ])('%s | maps to undefined', (_label, error) => {
    expect(toHttpErrorResponse(error)).toBeUndefined();
  });

  test('returns a copy of the headers', () => {
    const error = new PoppyUnavailableError();
    const response = responseFor(error);

    response.headers['retry-after'] = '999';
    response.headers['x-added'] = 'yes';
    delete response.headers['retry-after'];

    expect(error.headers).toEqual({ 'retry-after': '30' });
  });

  test('returns a copy of the header arrays too', () => {
    const error = new SignInRequiredError({ scope: 'orders:write' });
    const challenges = responseFor(error).headers['www-authenticate'];
    if (!Array.isArray(challenges)) {
      throw new Error('Expected the challenges to be an array.');
    }

    expect(challenges).toEqual(error.headers?.['www-authenticate']);
    expect(challenges).not.toBe(error.headers?.['www-authenticate']);

    challenges.push('Custom realm="x"');
    challenges[0] = 'Changed';

    expect(error.headers).toEqual({
      'www-authenticate': ['Bearer realm="api", scope="orders:write"', 'DPoP scope="orders:write", algs="ES256"'],
    });
  });

  test('returns empty headers for an error that has none', () => {
    const first = responseFor(new SessionEndedError());
    const second = responseFor(new SessionEndedError());

    first.headers['x-added'] = 'yes';

    expect(second.headers).toEqual({});
  });

  test('leaves error_description out when the message is empty', () => {
    expect(responseFor(new InvalidSessionError('claim_mismatch', '')).body).toStrictEqual({ error: 'invalid_session' });
    expect(responseFor(new SessionEndedError('')).body).toStrictEqual({ error: 'session_ended' });
    expect(responseFor(new PoppyUnavailableError('')).body).toStrictEqual({ error: 'temporarily_unavailable' });
  });

  test('gives access token errors no JSON body, whatever their message', () => {
    expect(responseFor(new VerifyAccessTokenError('A message.', INVALID_TOKEN_CHALLENGES)).body).toBeUndefined();
    expect(responseFor(signInRequired).body).toBeUndefined();
  });
});
