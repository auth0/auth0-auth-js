import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
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
import { setupServer } from '../test-utils/mock-http.js';

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

beforeAll(() => server.listen());
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
      expect(authenticators[0]).toEqual({
        id: 'totp|dev_123',
        authenticatorType: 'otp',
        active: true,
        name: 'Google Authenticator',
        oobChannels: undefined,
        type: undefined,
      });
      expect(authenticators[1]).toEqual({
        id: 'sms|dev_456',
        authenticatorType: 'oob',
        active: true,
        name: 'SMS',
        oobChannels: ['sms'],
        type: undefined,
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
        json: async () => mockAuthenticators,
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

  describe('verify', () => {
    let idToken: string;

    beforeAll(async () => {
      idToken = await generateToken(domain, 'user|123', clientId);
    });

    test('should verify OTP and return TokenResponse', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, async () =>
          HttpResponse.json({
            access_token: 'mfa_access_token',
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

      expect(result.accessToken).toBe('mfa_access_token');
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
            access_token: 'oob_access_token',
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
          })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      const result = await client.verify({ mfaToken, factorType: 'oob', oobCode: 'oob_123' });

      expect(result.accessToken).toBe('oob_access_token');
    });

    test('should verify recovery-code and set recoveryCode on TokenResponse', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, async () =>
          HttpResponse.json({
            access_token: 'recovery_access_token',
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
            recovery_code: 'NEW_RECOVERY_CODE',
          })
        )
      );

      const client = new MfaClient({ domain, clientId, getConfiguration: makeGetConfiguration(domain, clientId) });
      const result = await client.verify({ mfaToken, factorType: 'recovery-code', recoveryCode: 'OLD_CODE' });

      expect(result.accessToken).toBe('recovery_access_token');
      expect(result.recoveryCode).toBe('NEW_RECOVERY_CODE');
    });

    test('should include client_secret in token request', async () => {
      let capturedBody: FormData | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = await request.formData();
          return HttpResponse.json({
            access_token: 'token',
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
          return HttpResponse.json({ access_token: 'token', token_type: 'Bearer', expires_in: 86400 });
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
          return HttpResponse.json({ access_token: 'token', token_type: 'Bearer', expires_in: 86400 });
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
