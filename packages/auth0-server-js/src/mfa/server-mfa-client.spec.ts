import { expect, test, describe, afterAll, afterEach, beforeAll } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ServerClient } from '../server-client.js';
import { generateToken } from '../test-utils/tokens.js';
import { DefaultStateStore } from '../test-utils/default-state-store.js';
import { DefaultTransactionStore } from '../test-utils/default-transaction-store.js';
import { MfaVerifyError } from './errors.js';
import {
  MfaListAuthenticatorsError,
  MfaEnrollmentError,
} from '@auth0/auth0-auth-js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const mfaToken = 'test-mfa-token';

let idToken: string;

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

const buildOpenIdConfiguration = (customDomain: string) => ({
  issuer: `https://${customDomain}/`,
  authorization_endpoint: `https://${customDomain}/authorize`,
  token_endpoint: `https://${customDomain}/custom/token`,
  end_session_endpoint: `https://${customDomain}/logout`,
  pushed_authorization_request_endpoint: `https://${customDomain}/pushed-authorize`,
});

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(buildOpenIdConfiguration(domain));
  }),

  // MFA: List authenticators
  http.get(`https://${domain}/mfa/authenticators`, ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }
    return HttpResponse.json(mockAuthenticators);
  }),

  // MFA: Enroll authenticator
  http.post(`https://${domain}/mfa/associate`, async ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }

    const body = (await request.json()) as { authenticator_types: string[] };
    if (body.authenticator_types[0] === 'otp') {
      return HttpResponse.json({
        authenticator_type: 'otp',
        secret: 'JBSWY3DPEHPK3PXP',
        barcode_uri: 'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test',
      });
    }

    return HttpResponse.json(
      { error: 'unsupported_authenticator_type', error_description: 'Unsupported type' },
      { status: 400 }
    );
  }),

  // MFA: Delete authenticator
  http.delete(`https://${domain}/mfa/authenticators/:authenticatorId`, ({ request }) => {
    const authHeader = request.headers.get('Authorization');
    if (authHeader !== `Bearer ${mfaToken}`) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }
    return new HttpResponse(null, { status: 204 });
  }),

  // MFA: Challenge authenticator
  http.post(`https://${domain}/mfa/challenge`, async ({ request }) => {
    const body = (await request.json()) as { mfa_token?: string; challenge_type: string };

    if (body.mfa_token !== mfaToken) {
      return HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid MFA token' }, { status: 401 });
    }

    if (body.challenge_type === 'otp') {
      return HttpResponse.json({ challenge_type: 'otp' });
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

  // MFA: Verify (token endpoint)
  http.post(`https://${domain}/oauth/token`, async ({ request }) => {
    const body = (await request.json()) as {
      grant_type: string;
      client_id: string;
      client_secret?: string;
      mfa_token: string;
      otp?: string;
      oob_code?: string;
      binding_code?: string;
      recovery_code?: string;
    };

    if (body.mfa_token !== mfaToken) {
      return HttpResponse.json(
        { error: 'invalid_grant', error_description: 'Malformed mfa_token' },
        { status: 403 }
      );
    }

    if (body.grant_type === 'http://auth0.com/oauth/grant-type/mfa-otp') {
      if (body.otp !== '123456') {
        return HttpResponse.json(
          { error: 'invalid_grant', error_description: 'Invalid otp' },
          { status: 403 }
        );
      }

      return HttpResponse.json({
        access_token: 'mfa_access_token',
        id_token: idToken,
        refresh_token: 'mfa_refresh_token',
        token_type: 'Bearer',
        expires_in: 86400,
        scope: 'openid profile email',
      });
    }

    if (body.grant_type === 'http://auth0.com/oauth/grant-type/mfa-oob') {
      return HttpResponse.json({
        access_token: 'mfa_oob_access_token',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 86400,
        scope: 'openid profile email',
      });
    }

    if (body.grant_type === 'http://auth0.com/oauth/grant-type/mfa-recovery') {
      return HttpResponse.json({
        access_token: 'mfa_recovery_access_token',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 86400,
        scope: 'openid profile email',
        recovery_code: 'NEW_RECOVERY_CODE',
      });
    }

    return HttpResponse.json(
      { error: 'unsupported_grant_type', error_description: 'Unsupported grant type' },
      { status: 400 }
    );
  }),
];

const server = setupServer(...restHandlers);

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'error' });
  idToken = await generateToken(domain, 'user|123');
});
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

function createServerClient() {
  return new ServerClient({
    domain,
    clientId,
    clientSecret,
    transactionStore: new DefaultTransactionStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
    stateStore: new DefaultStateStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
  });
}

describe('ServerMfaClient', () => {
  describe('mfa property', () => {
    test('should be accessible on ServerClient', () => {
      const client = createServerClient();
      expect(client.mfa).toBeDefined();
    });
  });

  describe('listAuthenticators', () => {
    test('should list authenticators via authClient.mfa', async () => {
      const client = createServerClient();

      const authenticators = await client.mfa.listAuthenticators({ mfaToken });

      expect(authenticators).toHaveLength(2);
      expect(authenticators[0]).toEqual({
        id: 'totp|dev_123',
        authenticatorType: 'otp',
        active: true,
        name: 'Google Authenticator',
        oobChannels: undefined,
        type: undefined,
      });
    });

    test('should throw MfaListAuthenticatorsError on invalid token', async () => {
      const client = createServerClient();

      await expect(client.mfa.listAuthenticators({ mfaToken: 'invalid' })).rejects.toThrow(
        MfaListAuthenticatorsError
      );
    });
  });

  describe('enrollAuthenticator', () => {
    test('should enroll OTP authenticator via authClient.mfa', async () => {
      const client = createServerClient();

      const response = await client.mfa.enrollAuthenticator({
        authenticatorTypes: ['otp'],
        mfaToken,
      });

      expect(response).toHaveProperty('authenticatorType', 'otp');
      expect(response).toHaveProperty('secret');
      expect(response).toHaveProperty('barcodeUri');
    });

    test('should throw MfaEnrollmentError on failure', async () => {
      const client = createServerClient();

      await expect(
        client.mfa.enrollAuthenticator({
          authenticatorTypes: ['recovery-code'] as unknown as ['otp'],
          mfaToken,
        })
      ).rejects.toThrow(MfaEnrollmentError);
    });
  });

  describe('deleteAuthenticator', () => {
    test('should delete authenticator via authClient.mfa', async () => {
      const client = createServerClient();

      await expect(
        client.mfa.deleteAuthenticator({ authenticatorId: 'totp|dev_123', mfaToken })
      ).resolves.toBeUndefined();
    });
  });

  describe('challengeAuthenticator', () => {
    test('should challenge OTP authenticator via authClient.mfa', async () => {
      const client = createServerClient();

      const response = await client.mfa.challengeAuthenticator({
        challengeType: 'otp',
        mfaToken,
      });

      expect(response).toHaveProperty('challengeType', 'otp');
    });

    test('should challenge OOB authenticator via authClient.mfa', async () => {
      const client = createServerClient();

      const response = await client.mfa.challengeAuthenticator({
        challengeType: 'oob',
        mfaToken,
      });

      expect(response).toHaveProperty('challengeType', 'oob');
      expect(response).toHaveProperty('oobCode');
      expect(response).toHaveProperty('bindingMethod');
    });
  });

  describe('verify', () => {
    test('should verify OTP and return tokens', async () => {
      const client = createServerClient();

      const result = await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
      });

      expect(result.accessToken).toBe('mfa_access_token');
      expect(result.idToken).toBe(idToken);
      expect(result.refreshToken).toBe('mfa_refresh_token');
      expect(result.tokenType).toBe('Bearer');
      expect(result.expiresIn).toBe(86400);
      expect(result.scope).toBe('openid profile email');
    });

    test('should verify OOB and return tokens', async () => {
      const client = createServerClient();

      const result = await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-oob',
        oobCode: 'oob_code_123',
      });

      expect(result.accessToken).toBe('mfa_oob_access_token');
      expect(result.idToken).toBe(idToken);
      expect(result.tokenType).toBe('Bearer');
    });

    test('should verify recovery code and return new recovery code', async () => {
      const client = createServerClient();

      const result = await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-recovery',
        recoveryCode: 'ABCDEFGH12345678',
      });

      expect(result.accessToken).toBe('mfa_recovery_access_token');
      expect(result.recoveryCode).toBe('NEW_RECOVERY_CODE');
    });

    test('should persist state with updateStateData after OTP verification', async () => {
      const client = createServerClient();

      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
      });

      // Verify state was persisted - getSession should return the user data
      const session = await client.getSession();

      expect(session).toBeDefined();
      expect(session!.user).toBeDefined();
      expect(session!.user!.sub).toBe('user|123');
      expect(session!.idToken).toBe(idToken);
      expect(session!.refreshToken).toBe('mfa_refresh_token');
      expect(session!.tokenSets).toHaveLength(1);
      expect(session!.tokenSets[0]!.accessToken).toBe('mfa_access_token');
      expect(session!.tokenSets[0]!.audience).toBe('default');
      expect(session!.tokenSets[0]!.scope).toBe('openid profile email');
    });

    test('should persist state with custom audience', async () => {
      const client = new ServerClient({
        domain,
        clientId,
        clientSecret,
        authorizationParams: {
          audience: 'https://api.example.com',
        },
        transactionStore: new DefaultTransactionStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
        stateStore: new DefaultStateStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
      });

      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
      });

      const session = await client.getSession();
      expect(session!.tokenSets[0]!.audience).toBe('https://api.example.com');
    });

    test('should allow overriding audience in verify options', async () => {
      const client = createServerClient();

      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
        audience: 'https://custom-api.example.com',
      });

      const session = await client.getSession();
      expect(session!.tokenSets[0]!.audience).toBe('https://custom-api.example.com');
    });

    test('should update existing state (step-up MFA scenario)', async () => {
      const client = createServerClient();

      // First verify to establish initial state
      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
      });

      // Second verify with different audience (step-up)
      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
        audience: 'https://step-up-api.example.com',
      });

      const session = await client.getSession();
      expect(session!.tokenSets).toHaveLength(2);
      expect(session!.tokenSets.find((ts) => ts.audience === 'default')).toBeDefined();
      expect(session!.tokenSets.find((ts) => ts.audience === 'https://step-up-api.example.com')).toBeDefined();
    });

    test('should include client_secret in token request', async () => {
      let capturedBody: Record<string, string> | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, string>;
          return HttpResponse.json({
            access_token: 'test_access_token',
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
            scope: 'openid profile email',
          });
        })
      );

      const client = createServerClient();

      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
      });

      expect(capturedBody).toBeDefined();
      expect(capturedBody!.client_id).toBe(clientId);
      expect(capturedBody!.client_secret).toBe(clientSecret);
      expect(capturedBody!.mfa_token).toBe(mfaToken);
      expect(capturedBody!.grant_type).toBe('http://auth0.com/oauth/grant-type/mfa-otp');
      expect(capturedBody!.otp).toBe('123456');
    });

    test('should include oob_code and binding_code for OOB verification', async () => {
      let capturedBody: Record<string, string> | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, string>;
          return HttpResponse.json({
            access_token: 'test_access_token',
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
          });
        })
      );

      const client = createServerClient();

      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-oob',
        oobCode: 'oob_code_123',
        bindingCode: 'binding_456',
      });

      expect(capturedBody!.oob_code).toBe('oob_code_123');
      expect(capturedBody!.binding_code).toBe('binding_456');
    });

    test('should include recovery_code for recovery verification', async () => {
      let capturedBody: Record<string, string> | undefined;

      server.use(
        http.post(`https://${domain}/oauth/token`, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, string>;
          return HttpResponse.json({
            access_token: 'test_access_token',
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 86400,
            recovery_code: 'NEW_CODE',
          });
        })
      );

      const client = createServerClient();

      await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-recovery',
        recoveryCode: 'OLD_CODE',
      });

      expect(capturedBody!.recovery_code).toBe('OLD_CODE');
    });

    test('should throw MfaVerifyError on invalid MFA token', async () => {
      const client = createServerClient();

      await expect(
        client.mfa.verify({
          mfaToken: 'invalid-token',
          grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
          otp: '123456',
        })
      ).rejects.toThrow(MfaVerifyError);
    });

    test('should throw MfaVerifyError on invalid OTP code', async () => {
      const client = createServerClient();

      await expect(
        client.mfa.verify({
          mfaToken,
          grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
          otp: 'wrong-code',
        })
      ).rejects.toThrow(MfaVerifyError);
    });

    test('should throw MfaVerifyError with error details', async () => {
      const client = createServerClient();

      try {
        await client.mfa.verify({
          mfaToken: 'invalid-token',
          grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
          otp: '123456',
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(MfaVerifyError);
        const mfaError = error as MfaVerifyError;
        expect(mfaError.code).toBe('mfa_verify_error');
        expect(mfaError.cause).toBeDefined();
        expect(mfaError.cause!.error).toBe('invalid_grant');
        expect(mfaError.cause!.error_description).toBe('Malformed mfa_token');
      }
    });

    test('should handle verify response without id_token', async () => {
      server.use(
        http.post(`https://${domain}/oauth/token`, async () => {
          return HttpResponse.json({
            access_token: 'access_only',
            token_type: 'Bearer',
            expires_in: 86400,
            scope: 'openid',
          });
        })
      );

      const client = createServerClient();

      const result = await client.mfa.verify({
        mfaToken,
        grantType: 'http://auth0.com/oauth/grant-type/mfa-otp',
        otp: '123456',
      });

      expect(result.accessToken).toBe('access_only');
      expect(result.idToken).toBeUndefined();
      expect(result.refreshToken).toBeUndefined();
    });
  });
});
