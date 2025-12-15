import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MfaClient } from './mfa-client.js';
import {
  MfaListAuthenticatorsError,
  MfaDeleteAuthenticatorError,
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
    created_at: '2024-01-01T00:00:00.000Z',
  },
  {
    id: 'sms|dev_456',
    authenticator_type: 'oob',
    active: true,
    name: 'SMS',
    created_at: '2024-01-02T00:00:00.000Z',
  },
];

const restHandlers = [
  // List authenticators
  http.get(`https://${domain}/mfa/authenticators`, ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json(
        { error: 'invalid_token', error_description: 'Invalid MFA token' },
        { status: 401 }
      );
    }
    return HttpResponse.json(mockAuthenticators);
  }),

  // Enroll authenticator
  http.post(`https://${domain}/mfa/associate`, async ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json(
        { error: 'invalid_token', error_description: 'Invalid MFA token' },
        { status: 401 }
      );
    }

    const body = (await request.json()) as { authenticator_types: string[] };
    if (body.authenticator_types[0] === 'otp') {
      return HttpResponse.json({
        authenticator_type: 'otp',
        secret: 'JBSWY3DPEHPK3PXP',
        barcode_uri:
          'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test',
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
      return HttpResponse.json(
        { error: 'invalid_token', error_description: 'Invalid MFA token' },
        { status: 401 }
      );
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
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json(
        { error: 'invalid_token', error_description: 'Invalid MFA token' },
        { status: 401 }
      );
    }

    const body = (await request.json()) as { challenge_type: string };
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
      expect(authenticators[0]).toEqual(mockAuthenticators[0]);
      expect(authenticators[1]).toEqual(mockAuthenticators[1]);
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
        authenticator_types: ['otp'],
        mfaToken,
      });

      expect(response).toHaveProperty('authenticator_type', 'otp');
      expect(response).toHaveProperty('secret');
      expect(response).toHaveProperty('barcode_uri');
    });
  });

  describe('deleteAuthenticator', () => {
    test('should delete authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.deleteAuthenticator({ authenticatorId: 'totp|dev_123', mfaToken })
      ).resolves.toBeUndefined();
    });

    test('should throw MfaDeleteAuthenticatorError on invalid authenticator ID', async () => {
      const client = new MfaClient({ domain, clientId });

      await expect(
        client.deleteAuthenticator({ authenticatorId: 'invalid-id', mfaToken })
      ).rejects.toThrow(MfaDeleteAuthenticatorError);
    });
  });

  describe('challengeAuthenticator', () => {
    test('should challenge OTP authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.challengeAuthenticator({
        challenge_type: 'otp',
        mfaToken,
      });

      expect(response).toHaveProperty('challenge_type', 'otp');
    });

    test('should challenge OOB authenticator successfully', async () => {
      const client = new MfaClient({ domain, clientId });

      const response = await client.challengeAuthenticator({
        challenge_type: 'oob',
        mfaToken,
      });

      expect(response).toHaveProperty('challenge_type', 'oob');
      expect(response).toHaveProperty('oob_code');
      expect(response).toHaveProperty('binding_method');
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
