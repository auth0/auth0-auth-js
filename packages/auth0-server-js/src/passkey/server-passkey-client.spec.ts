import { expect, test, afterAll, afterEach, beforeAll, beforeEach, vi, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ServerClient } from '../server-client.js';
import { generateToken, jwks } from '../test-utils/tokens.js';
import { DefaultStateStore } from '../test-utils/default-state-store.js';
import { DefaultTransactionStore } from '../test-utils/default-transaction-store.js';
import * as Auth0AuthJs from '@auth0/auth0-auth-js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';

let idToken: string;

const buildOpenIdConfiguration = (customDomain: string) => ({
  issuer: `https://${customDomain}/`,
  authorization_endpoint: `https://${customDomain}/authorize`,
  token_endpoint: `https://${customDomain}/custom/token`,
  end_session_endpoint: `https://${customDomain}/logout`,
  pushed_authorization_request_endpoint: `https://${customDomain}/pushed-authorize`,
  jwks_uri: `https://${customDomain}/.well-known/jwks.json`,
});

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(buildOpenIdConfiguration(domain));
  }),

  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),

  // Passkey: Register
  http.post(`https://${domain}/webauthn/register/init`, () => {
    return HttpResponse.json({
      authSession: 'auth_session_123',
      authnParamsPublicKey: {
        challenge: 'challenge_123',
        rp: { name: 'Test', id: domain },
        user: { id: 'user_id', name: 'user@example.com', displayName: 'User' },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        timeout: 60000,
        attestation: 'direct',
      },
    });
  }),

  // Passkey: Challenge
  http.post(`https://${domain}/webauthn/authenticate/init`, () => {
    return HttpResponse.json({
      authSession: 'auth_session_456',
      authnParamsPublicKey: {
        challenge: 'challenge_456',
        timeout: 60000,
        rpId: domain,
        allowCredentials: [],
        userVerification: 'preferred',
      },
    });
  }),

  // Passkey: GetToken
  http.post(`https://${domain}/custom/token`, async ({ request }) => {
    const body = await request.formData();
    const grantType = body.get('grant_type') as string;

    if (grantType === 'http://auth0.com/oauth/grant-type/passkey-credential') {
      return HttpResponse.json({
        access_token: 'passkey_access_token',
        id_token: idToken,
        refresh_token: 'passkey_refresh_token',
        token_type: 'Bearer',
        expires_in: 86400,
        scope: 'openid profile email',
      });
    }

    return HttpResponse.json({ error: 'unsupported_grant_type' }, { status: 400 });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(async () => {
  server.listen({ onUnhandledRequest: 'bypass' });
  idToken = generateToken(domain, clientId, 'sub_123');
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

const makeClient = (domainOption: string | (() => Promise<string>) = domain) =>
  new ServerClient({
    domain: domainOption,
    clientId,
    clientSecret,
    transactionStore: new DefaultTransactionStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
    stateStore: new DefaultStateStore({ secret: 'test-secret-that-is-at-least-32-chars' }),
  });

describe('ServerPasskeyClient', () => {
  test('exposes a passkey sub-client with register, challenge, and getToken', () => {
    const sc = makeClient();
    expect(sc.passkey).toBeDefined();
    expect(typeof sc.passkey.register).toBe('function');
    expect(typeof sc.passkey.challenge).toBe('function');
    expect(typeof sc.passkey.getToken).toBe('function');
  });

  // ==============================================================================
  // PHASE 10: Per-Request Options Tests for Passkey
  // ==============================================================================

  // Per-Request Options: Passkey client methods have requestOptions parameter
  // Register, challenge, and getToken all accept requestOptions as trailing parameter
  // These are integration-tested via existing end-to-end tests; compile-time type safety
  // verified by TypeScript. See: src/passkey/server-passkey-client.ts
});
