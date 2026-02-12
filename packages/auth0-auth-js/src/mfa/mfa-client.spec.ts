import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MfaClient } from './mfa-client.js';
import {
  MfaListAuthenticatorsError,
  MfaDeleteAuthenticatorError,
  MfaEnrollmentError,
  MfaChallengeError,
} from './errors.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
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
});
