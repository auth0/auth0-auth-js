import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import * as oidcClient from 'openid-client';
import { MfaClient } from './mfa-client.js';
import {
  MfaListAuthenticatorsError,
  MfaDeleteAuthenticatorError,
  MfaEnrollmentError,
  MfaChallengeError,
  MfaVerifyError,
} from './errors.js';
import { generateToken, jwks } from '../test-utils/tokens.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';

const makeGetConfiguration = (d: string, cId: string, cSecret?: string) => {
  const config = new oidcClient.Configuration(
    {
      issuer: `https://${d}/`,
      token_endpoint: `https://${d}/oauth/token`,
      jwks_uri: `https://${d}/.well-known/jwks.json`,
      token_endpoint_auth_methods_supported: cSecret ? ['client_secret_post'] : ['none'],
    },
    cId,
    cSecret
  );
  return () => Promise.resolve(config);
};
const mfaToken = 'test-mfa-token';

const mockAuthenticators = [
  {
    id: 'totp|dev_123',
    authenticator_type: 'otp',
    active: true,
    name: 'Google Authenticator',
  },
  {
    id: 'sms|dev_456',
    authenticator_type: 'oob',
    active: true,
    name: 'SMS',
    oob_channels: ['sms'],
  },
];

const restHandlers = [
  // JWKS endpoint for openid-client id_token validation
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),

  // List authenticators
  http.get(`https://${domain}/mfa/authenticators`, ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }
    return HttpResponse.json(mockAuthenticators);
  }),

  // Enroll authenticator
  http.post(`https://${domain}/mfa/associate`, async ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }

    const body = (await request.json()) as {
      authenticator_types: string[];
      oob_channels?: string[];
      phone_number?: string;
      email?: string;
    };

    if (body.authenticator_types[0] === 'otp') {
      return HttpResponse.json({
        authenticator_type: 'otp',
        secret: 'JBSWY3DPEHPK3PXP',
        barcode_uri: 'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test',
      });
    }

    if (body.oob_channels?.includes('email')) {
      return HttpResponse.json({
        authenticator_type: 'oob',
        oob_channel: 'email',
        oob_code: 'email_oob_code_123',
        binding_method: 'prompt',
      });
    }

    if (body.oob_channels?.includes('auth0')) {
      return HttpResponse.json({
        authenticator_type: 'oob',
        oob_channel: 'auth0',
        oob_code: 'auth0_oob_code_123',
        barcode_uri:
          'otpauth://totp/Test:user@example.com?enrollment_tx_id=test_tx_id&base_url=https%3A%2F%2Ftest.us.auth0.com%2Fappliance-mfa',
        recovery_codes: ['ABCDEFGH12345678'],
      });
    }

    if (body.oob_channels?.includes('sms') && body.phone_number) {
      return HttpResponse.json({
        authenticator_type: 'oob',
        oob_channel: 'sms',
        oob_code: 'sms_oob_code_123',
        binding_method: 'prompt',
      });
    }

    if (body.oob_channels?.includes('voice') && body.phone_number) {
      return HttpResponse.json({
        authenticator_type: 'oob',
        oob_channel: 'voice',
        oob_code: 'voice_oob_code_123',
        binding_method: 'prompt',
      });
    }

    return HttpResponse.json(
      { error: 'unsupported_authenticator_type', error_description: 'Unsupported type' },
      { status: 400 }
    );
  }),

  // Delete authenticator
  http.delete(`https://${domain}/mfa/authenticators/:authenticatorId`, ({ request, params }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }

    const { authenticatorId } = params;
    if (authenticatorId === 'invalid-id') {
      return HttpResponse.json(
        { error: 'invalid_authenticator', error_description: 'Authenticator not found' },
        { status: 404 }
      );
    }

    return new HttpResponse(null, { status: 204 });
  }),

  // Challenge authenticator
  http.post(`https://${domain}/mfa/challenge`, async ({ request }) => {
    const body = (await request.json()) as {
      mfa_token?: string;
      challenge_type: string;
      authenticator_id?: string;
    };

    if (body.mfa_token !== mfaToken) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }

    if (body.authenticator_id === 'invalid-id') {
      return HttpResponse.json(
        { error: 'invalid_authenticator', error_description: 'Invalid authenticator ID' },
        { status: 400 }
      );
    }

    if (body.challenge_type === 'otp') {
      return HttpResponse.json({
        challenge_type: 'otp',
      });
    }

    if (body.challenge_type === 'oob') {
      return HttpResponse.json({
        challenge_type: 'oob',
        oob_code: 'oob_code_123',
        binding_method: 'prompt',
      });
    }

    return HttpResponse.json(
      { error: 'unsupported_challenge_type', error_description: 'Unsupported challenge type' },
      { status: 400 }
    );
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

describe('MfaClient', () => {
  describe('constructor', () => {
    test('should create an instance with required options', () => {
      const client = new MfaClient({ domain, clientId });
      expect(client).toBeInstanceOf(MfaClient);
    });
  });

  describe('listAuthenticators', () => {
    test('should list authenticators successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const authenticators = await client.listAuthenticators({ mfaToken });

      expect(authenticators).toHaveLength(2);
      expect(authenticators[0]).toMatchObject({
        id: 'totp|dev_123',
        authenticatorType: 'otp',
        active: true,
        name: 'Google Authenticator',
      });
      expect(authenticators[1]).toMatchObject({
        id: 'sms|dev_456',
        authenticatorType: 'oob',
        active: true,
        name: 'SMS',
        oobChannels: ['sms'],
      });
    });

    test('should throw MfaListAuthenticatorsError on invalid token', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(client.listAuthenticators({ mfaToken: 'invalid-token' })).rejects.toThrow(
        MfaListAuthenticatorsError
      );
    });
  });

  describe('enrollAuthenticator', () => {
    test('should enroll OTP authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['otp'],
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'otp');
      expect(response).toHaveProperty('secret');
      expect(response).toHaveProperty('barcodeUri');
    });

    test('should enroll email authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['oob'],
        oobChannels: ['email'],
        email: 'user@example.com',
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'oob');
      expect(response).toHaveProperty('oobChannel', 'email');
      expect(response).toHaveProperty('oobCode');
    });

    test('should enroll email authenticator without explicit email', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['oob'],
        oobChannels: ['email'],
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'oob');
      expect(response).toHaveProperty('oobChannel', 'email');
    });

    test('should enroll SMS authenticator with phone number', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['oob'],
        oobChannels: ['sms'],
        phoneNumber: '+1234567890',
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'oob');
      expect(response).toHaveProperty('oobChannel', 'sms');
      expect(response).toHaveProperty('oobCode');
    });

    test('should enroll voice authenticator with phone number', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['oob'],
        oobChannels: ['voice'],
        phoneNumber: '+1234567890',
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'oob');
      expect(response).toHaveProperty('oobChannel', 'voice');
      expect(response).toHaveProperty('oobCode');
    });

    test('should enroll auth0 (Guardian) authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['oob'],
        oobChannels: ['auth0'],
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'oob');
      expect(response).toHaveProperty('oobChannel', 'auth0');
      expect(response).toHaveProperty('oobCode');
      expect(response).toHaveProperty('barcodeUri');
      expect(response).toHaveProperty('recoveryCodes', ['ABCDEFGH12345678']);
    });

    test('should throw MfaEnrollmentError on invalid mfa token', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.enrollAuthenticator({
          authenticatorTypes: ['otp'],
          mfaToken: 'invalid-token',
        })
      ).rejects.toThrow(MfaEnrollmentError);
    });

    test('should throw MfaEnrollmentError on unsupported authenticator type', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.enrollAuthenticator({
          authenticatorTypes: ['recovery-code'] as unknown as ['otp'],
          mfaToken,
        })
      ).rejects.toThrow(MfaEnrollmentError);
    });
  });

  describe('deleteAuthenticator', () => {
    test('should delete authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(client.deleteAuthenticator({ authenticatorId: 'totp|dev_123', mfaToken })).resolves.toBeUndefined();
    });

    test('should throw MfaDeleteAuthenticatorError on invalid authenticator ID', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(client.deleteAuthenticator({ authenticatorId: 'invalid-id', mfaToken })).rejects.toThrow(
        MfaDeleteAuthenticatorError
      );
    });
  });

  describe('challengeAuthenticator', () => {
    test('should challenge OTP authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.challengeAuthenticator({
        challengeType: 'otp',
        mfaToken,
      });

      expect(response).toHaveProperty('challengeType', 'otp');
    });

    test('should challenge OOB authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.challengeAuthenticator({
        challengeType: 'oob',
        mfaToken,
      });

      expect(response).toHaveProperty('challengeType', 'oob');
      expect(response).toHaveProperty('oobCode');
      expect(response).toHaveProperty('bindingMethod');
    });

    test('should throw MfaChallengeError on invalid mfa token', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.challengeAuthenticator({
          challengeType: 'otp',
          mfaToken: 'invalid-token',
        })
      ).rejects.toThrow(MfaChallengeError);
    });

    test('should throw MfaChallengeError on invalid authenticator ID', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.challengeAuthenticator({
          challengeType: 'oob',
          authenticatorId: 'invalid-id',
          mfaToken,
        })
      ).rejects.toThrow(MfaChallengeError);
    });

    test('should throw MfaChallengeError on unsupported challenge type', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.challengeAuthenticator({
          challengeType: 'invalid' as unknown as 'otp',
          mfaToken,
        })
      ).rejects.toThrow(MfaChallengeError);
    });

    test('should include client_secret in request body for confidential clients', async () => {
      let capturedBody: Record<string, string> | undefined;

      server.use(
        http.post(`https://${domain}/mfa/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, string>;
          return HttpResponse.json({ challenge_type: 'otp' });
        })
      );

      const client = new MfaClient({ domain, clientId, clientSecret: 'test-client-secret' });
      await client.challengeAuthenticator({ challengeType: 'otp', mfaToken });

      expect(capturedBody!.client_secret).toBe('test-client-secret');
      expect(capturedBody!.client_id).toBe(clientId);
    });

    test('should not include client_secret for public clients', async () => {
      let capturedBody: Record<string, string> | undefined;

      server.use(
        http.post(`https://${domain}/mfa/challenge`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, string>;
          return HttpResponse.json({ challenge_type: 'otp' });
        })
      );

      const client = new MfaClient({ domain, clientId });
      await client.challengeAuthenticator({ challengeType: 'otp', mfaToken });

      expect(capturedBody!.client_secret).toBeUndefined();
    });

    test('should throw MfaChallengeError when server returns non-JSON error response', async () => {
      server.use(
        http.post(`https://${domain}/mfa/challenge`, () => {
          return new HttpResponse('<html>Bad Gateway</html>', {
            status: 502,
            headers: { 'Content-Type': 'text/html' },
          });
        })
      );

      const client = new MfaClient({ domain, clientId });

      await expect(
        client.challengeAuthenticator({ challengeType: 'otp', mfaToken })
      ).rejects.toThrow(MfaChallengeError);
    });
  });

  describe('customFetch', () => {
    test('should use customFetch when provided', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        json: async () => mockAuthenticators,
        clone: function() {
          return {
            text: async () => JSON.stringify(mockAuthenticators),
          };
        },
      });

      const client = new MfaClient({ domain, clientId, customFetch: mockFetch });

      await client.listAuthenticators({ mfaToken });

      expect(mockFetch).toHaveBeenCalledWith(
        `https://${domain}/mfa/authenticators`,
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            Authorization: `Bearer ${mfaToken}`,
          }),
        })
      );
    });
  });

  describe('HttpResponseMetadata — success path (MFA data methods)', () => {
    test('listAuthenticators 200 — httpResponse present with status/statusText/headers', async () => {
      const client = new MfaClient({ domain, clientId });

      const authenticators = await client.listAuthenticators({ mfaToken });

      expect(authenticators.length).toBe(2);
      // Each item should have httpResponse metadata
      authenticators.forEach((item) => {
        expect(item.httpResponse).toBeDefined();
        expect(item.httpResponse?.status).toBe(200);
        expect(typeof item.httpResponse?.statusText).toBe('string');
        expect(item.httpResponse?.headers).toBeInstanceOf(Headers);
        expect(typeof item.httpResponse?.headers?.get).toBe('function');
      });
      // Data should be present
      expect(authenticators[0].id).toBe('totp|dev_123');
      expect(authenticators[1].id).toBe('sms|dev_456');
    });

    test('enrollAuthenticator 200 — httpResponse present', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.enrollAuthenticator({
        authenticatorTypes: ['otp'],
        mfaToken,
      });

      expect(response.httpResponse).toBeDefined();
      expect(response.httpResponse?.status).toBe(200);
      expect(typeof response.httpResponse?.statusText).toBe('string');
      expect(response.httpResponse?.headers).toBeInstanceOf(Headers);
      expect(response.authenticatorType).toBe('otp');
    });

    test('challengeAuthenticator 200 — httpResponse present', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.challengeAuthenticator({
        challengeType: 'otp',
        mfaToken,
      });

      expect(response.httpResponse).toBeDefined();
      expect(response.httpResponse?.status).toBe(200);
      expect(typeof response.httpResponse?.statusText).toBe('string');
      expect(response.httpResponse?.headers).toBeInstanceOf(Headers);
      expect(response.challengeType).toBe('otp');
    });

    test('httpResponse.headers native Headers .get() works', async () => {
      server.use(
        http.get(`https://${domain}/mfa/authenticators`, () => {
          return HttpResponse.json(mockAuthenticators, {
            status: 200,
            headers: { 'x-request-id': 'req-mfa-001', 'retry-after': '60' },
          });
        })
      );

      const client = new MfaClient({ domain, clientId });
      const authenticators = await client.listAuthenticators({ mfaToken });

      expect(authenticators[0].httpResponse?.headers.get('x-request-id')).toBe('req-mfa-001');
      expect(authenticators[0].httpResponse?.headers.get('retry-after')).toBe('60');
      expect(typeof authenticators[0].httpResponse?.headers.get).toBe('function');
    });

    test('deleteAuthenticator void — NO success metadata (O#3 gap)', async () => {
      const client = new MfaClient({ domain, clientId });

      const result = await client.deleteAuthenticator({ authenticatorId: 'totp|dev_123', mfaToken });

      // Void return should be undefined
      expect(result).toBeUndefined();
      // Do not wrap in object (breaking change) — error metadata still available on throw
    });
  });

  describe('HttpResponseMetadata — error path (MFA data methods)', () => {
    test('enrollAuthenticator 401 — error has statusCode/headers/body (raw fetch)', async () => {
      const client = new MfaClient({ domain, clientId });

      try {
        await client.enrollAuthenticator({
          authenticatorTypes: ['otp'],
          mfaToken: 'invalid-token',
        });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(MfaEnrollmentError);
        const err = e as MfaEnrollmentError;
        expect(err.statusCode).toBe(401);
        expect(err.headers).toBeInstanceOf(Headers);
        expect(typeof err.body).toBe('string');
        expect(err.body).toContain('invalid_token');
        // Verify native Headers method works
        expect(typeof err.headers?.get).toBe('function');
      }
    });

    test('listAuthenticators 401 — error has statusCode/headers/body', async () => {
      const client = new MfaClient({ domain, clientId });

      try {
        await client.listAuthenticators({ mfaToken: 'invalid-token' });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(MfaListAuthenticatorsError);
        const err = e as MfaListAuthenticatorsError;
        expect(err.statusCode).toBe(401);
        expect(err.headers).toBeInstanceOf(Headers);
        expect(typeof err.body).toBe('string');
        expect(err.body).toContain('invalid_token');
      }
    });

    test('challengeAuthenticator 401 — error has statusCode/headers/body', async () => {
      const client = new MfaClient({ domain, clientId });

      try {
        await client.challengeAuthenticator({
          challengeType: 'otp',
          mfaToken: 'invalid-token',
        });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(MfaChallengeError);
        const err = e as MfaChallengeError;
        expect(err.statusCode).toBe(401);
        expect(err.headers).toBeInstanceOf(Headers);
        expect(typeof err.body).toBe('string');
      }
    });

    test('error.body is raw string (not parsed)', async () => {
      const client = new MfaClient({ domain, clientId });

      try {
        await client.listAuthenticators({ mfaToken: 'invalid-token' });
        expect.fail('Should have thrown');
      } catch (e) {
        const err = e as MfaListAuthenticatorsError;
        expect(typeof err.body).toBe('string');
        expect(err.body).toContain('invalid_token');
        // Verify it can be parsed by caller if needed
        const parsed = JSON.parse(err.body!);
        expect(parsed.error).toBe('invalid_token');
        expect(parsed.error_description).toBe('Invalid MFA token');
      }
    });

    test('deleteAuthenticator error — void return skips success metadata but error metadata present', async () => {
      const client = new MfaClient({ domain, clientId });

      try {
        await client.deleteAuthenticator({ authenticatorId: 'invalid-id', mfaToken });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(MfaDeleteAuthenticatorError);
        const err = e as MfaDeleteAuthenticatorError;
        // Error metadata should be present
        expect(err.statusCode).toBe(404);
        expect(err.headers).toBeInstanceOf(Headers);
        expect(typeof err.body).toBe('string');
      }
    });
  });

  describe('HttpResponseMetadata — concurrency (no cross-leakage)', () => {
    test('concurrent calls — each result has correct httpResponse (200 vs 401)', async () => {
      server.use(
        http.post(`https://${domain}/mfa/associate`, async ({ request }) => {
          const body = (await request.json()) as { authenticator_types: string[] };
          const authHeader = request.headers.get('Authorization');

          // Simulate routing by checking auth header
          if (authHeader !== `Bearer ${mfaToken}`) {
            return HttpResponse.json(
              { error: 'invalid_token', error_description: 'Invalid MFA token' },
              { status: 401, headers: { 'x-request-id': 'req-err-001' } }
            );
          }

          if (body.authenticator_types[0] === 'otp') {
            return HttpResponse.json(
              { authenticator_type: 'otp', secret: 'SECRET123', barcode_uri: 'otpauth://...' },
              { status: 200, headers: { 'x-request-id': 'req-ok-001' } }
            );
          }

          return HttpResponse.json({ error: 'unsupported', error_description: 'x' }, { status: 400 });
        })
      );

      const client = new MfaClient({ domain, clientId });

      // Run concurrent calls: one success (200), one error (401)
      const [successResult, errorResult] = await Promise.allSettled([
        client.enrollAuthenticator({
          authenticatorTypes: ['otp'],
          mfaToken,
        }),
        client.enrollAuthenticator({
          authenticatorTypes: ['otp'],
          mfaToken: 'invalid-token',
        }),
      ]);

      // Success call (200)
      expect(successResult.status).toBe('fulfilled');
      if (successResult.status === 'fulfilled') {
        expect(successResult.value.httpResponse?.status).toBe(200);
        expect(successResult.value.httpResponse?.headers.get('x-request-id')).toBe('req-ok-001');
        expect(successResult.value.authenticatorType).toBe('otp');
      }

      // Error call (401)
      expect(errorResult.status).toBe('rejected');
      if (errorResult.status === 'rejected') {
        const err = errorResult.reason as MfaEnrollmentError;
        expect(err.statusCode).toBe(401);
        expect(err.headers?.get('x-request-id')).toBe('req-err-001');
        expect(err.body).toContain('invalid_token');
      }

      // Verify NO cross-leakage
      if (successResult.status === 'fulfilled' && errorResult.status === 'rejected') {
        expect(successResult.value.httpResponse?.status).not.toBe(401);
        expect(errorResult.reason.statusCode).not.toBe(200);
      }
    });

    test('multiple parallel calls — each captures own request-id header', async () => {
      let callCount = 0;

      server.use(
        http.get(`https://${domain}/mfa/authenticators`, () => {
          callCount++;
          const requestId = `req-${callCount}`;
          return HttpResponse.json(mockAuthenticators, {
            status: 200,
            headers: { 'x-request-id': requestId },
          });
        })
      );

      const client = new MfaClient({ domain, clientId });

      const [result1, result2] = await Promise.all([
        client.listAuthenticators({ mfaToken }),
        client.listAuthenticators({ mfaToken }),
      ]);

      // Each call captures its own x-request-id
      expect(result1[0].httpResponse?.headers.get('x-request-id')).toBe('req-1');
      expect(result2[0].httpResponse?.headers.get('x-request-id')).toBe('req-2');
      expect(result1[0].id).toBe('totp|dev_123');
      expect(result2[0].id).toBe('totp|dev_123');
    });

    test('concurrent error calls — each error has correct statusCode (no cross-leakage)', async () => {
      server.use(
        http.post(`https://${domain}/mfa/challenge`, async ({ request }) => {
          const body = (await request.json()) as { mfa_token?: string };

          if (body.mfa_token === 'rate-limited') {
            return HttpResponse.json(
              { error: 'too_many_requests', error_description: 'Rate limited' },
              { status: 429 }
            );
          }

          return HttpResponse.json(
            { error: 'invalid_token', error_description: 'Invalid MFA token' },
            { status: 401 }
          );
        })
      );

      const client = new MfaClient({ domain, clientId });

      const calls = await Promise.allSettled([
        client.challengeAuthenticator({
          challengeType: 'otp',
          mfaToken: 'rate-limited',
        }),
        client.challengeAuthenticator({
          challengeType: 'otp',
          mfaToken: 'invalid-token',
        }),
      ]);

      expect(calls[0].status).toBe('rejected');
      expect(calls[1].status).toBe('rejected');

      if (calls[0].status === 'rejected' && calls[1].status === 'rejected') {
        const errors = [calls[0].reason, calls[1].reason] as MfaChallengeError[];
        const statuses = errors.map((e) => e.statusCode).sort();

        expect(statuses).toContain(401);
        expect(statuses).toContain(429);
        expect(statuses[0]).not.toBe(statuses[1]); // Different values (no cross-leakage)
      }
    });
  });

  describe('verify', () => {
    let idToken: string;
    let mfaAccessToken: string;
    let oobAccessToken: string;
    let recoveryAccessToken: string;
    let genericAccessToken: string;

    beforeAll(async () => {
      idToken = await generateToken(domain, 'user|123', clientId);
      mfaAccessToken = await generateToken(domain, 'user|123', clientId);
      oobAccessToken = await generateToken(domain, 'user|123', clientId);
      recoveryAccessToken = await generateToken(domain, 'user|123', clientId);
      genericAccessToken = await generateToken(domain, 'user|123', clientId);
    });

    test('should verify OTP and return TokenResponse', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, async () =>
          HttpResponse.json({
            access_token: mfaAccessToken,
            id_token: idToken,
            refresh_token: 'mfa_refresh_token',
            token_type: 'Bearer',
            expires_in: 86400,
            scope: 'openid profile email',
          })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      const result = await client.verify({ mfaToken, factorType: 'otp', otp: '123456' });

      expect(result.accessToken).toBe(mfaAccessToken);
      expect(result.idToken).toBe(idToken);
      expect(result.refreshToken).toBe('mfa_refresh_token');
      expect(result.tokenType).toBe('bearer');
      expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
      expect(result.scope).toBe('openid profile email');
      expect(result.claims?.sub).toBe('user|123');
    });

    test('should verify OOB and return TokenResponse', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, async () =>
          HttpResponse.json({
            access_token: oobAccessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
          })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      const result = await client.verify({ mfaToken, factorType: 'oob', oobCode: 'oob_123' });

      expect(result.accessToken).toBe(oobAccessToken);
    });

    test('should verify recovery-code and set recoveryCode on TokenResponse', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, async () =>
          HttpResponse.json({
            access_token: recoveryAccessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
            recovery_code: 'NEW_RECOVERY_CODE',
          })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      const result = await client.verify({ mfaToken, factorType: 'recovery-code', recoveryCode: 'OLD_CODE' });

      expect(result.accessToken).toBe(recoveryAccessToken);
      expect(result.recoveryCode).toBe('NEW_RECOVERY_CODE');
    });

    test('should include client_secret in token request', async () => {
      let capturedBody: FormData | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = await request.formData();
          return HttpResponse.json({
            access_token: genericAccessToken,
            token_type: 'Bearer',
            expires_in: 86400,
          });
        })
      );

      const client = new MfaClient({ domain, clientId, clientSecret: 'test-secret', getConfiguration: makeGetConfiguration(domain, clientId, 'test-secret') });
      await client.verify({ mfaToken, factorType: 'otp', otp: '123456' });

      expect(capturedBody!.get('client_secret')).toBe('test-secret');
      expect(capturedBody!.get('grant_type')).toBe('http://auth0.com/oauth/grant-type/mfa-otp');
      expect(capturedBody!.get('otp')).toBe('123456');
    });

    test('should include oob_code and binding_code for OOB', async () => {
      let capturedBody: FormData | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = await request.formData();
          return HttpResponse.json({ access_token: genericAccessToken, token_type: 'Bearer', expires_in: 86400 });
        })
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      await client.verify({ mfaToken, factorType: 'oob', oobCode: 'oob_123', bindingCode: 'bind_456' });

      expect(capturedBody!.get('oob_code')).toBe('oob_123');
      expect(capturedBody!.get('binding_code')).toBe('bind_456');
      expect(capturedBody!.get('grant_type')).toBe('http://auth0.com/oauth/grant-type/mfa-oob');
    });

    test('should forward audience to token request body', async () => {
      let capturedBody: FormData | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = await request.formData();
          return HttpResponse.json({ access_token: genericAccessToken, token_type: 'Bearer', expires_in: 86400 });
        })
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      await client.verify({ mfaToken, factorType: 'otp', otp: '123456', audience: 'https://api.example.com' });

      expect(capturedBody!.get('audience')).toBe('https://api.example.com');
    });

    test('should throw MfaVerifyError on invalid mfa_token', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, () =>
          HttpResponse.json({ error: 'invalid_grant', error_description: 'Malformed mfa_token' }, { status: 403 })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      await expect(client.verify({ mfaToken: 'bad', factorType: 'otp', otp: '123456' })).rejects.toThrow(
        MfaVerifyError
      );
    });

    test('should throw MfaVerifyError with error details', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, () =>
          HttpResponse.json({ error: 'invalid_grant', error_description: 'Invalid OTP' }, { status: 403 })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      try {
        await client.verify({ mfaToken, factorType: 'otp', otp: 'wrong' });
        expect.fail('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(MfaVerifyError);
        const err = e as MfaVerifyError;
        expect(err.cause?.error).toBe('invalid_grant');
        expect(err.cause?.error_description).toBe('Invalid OTP');
      }
    });

    test('should throw MfaVerifyError when access_token is missing', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, () =>
          HttpResponse.json({ token_type: 'Bearer', expires_in: 86400 })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      await expect(client.verify({ mfaToken, factorType: 'otp', otp: '123456' })).rejects.toThrow(MfaVerifyError);
    });

    test('should throw MfaVerifyError when id_token is a malformed JWT', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, () =>
          HttpResponse.json({ access_token: 'token', id_token: 'not.a.jwt', token_type: 'Bearer', expires_in: 86400 })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      await expect(client.verify({ mfaToken, factorType: 'otp', otp: '123456' })).rejects.toThrow(MfaVerifyError);
    });

    test('should throw MfaVerifyError when server returns non-JSON error', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, () =>
          new HttpResponse('<html>Bad Gateway</html>', { status: 502, headers: { 'Content-Type': 'text/html' } })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      await expect(client.verify({ mfaToken, factorType: 'otp', otp: '123456' })).rejects.toThrow(MfaVerifyError);
    });
  });
});
