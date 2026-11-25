import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import * as oidcClient from 'openid-client';
import { AuthClient } from './auth-client.js';
import { BackchannelAuthenticationError, TokenExchangeError, TokenForConnectionError } from './errors.js';
import { MfaVerifyError } from './mfa/errors.js';
import { PasskeyGetTokenError } from './passkey/errors.js';
import { PasswordlessDbGetTokenError } from './passwordless/errors.js';
import type { RequestOptions } from './types.js';

const domain = 'auth0.local';
const tokenEndpoint = `https://${domain}/oauth/token`;
const NONCE = 'server-nonce-1';

const server = setupServer(
  http.get(`https://${domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json({
      issuer: `https://${domain}/`,
      authorization_endpoint: `https://${domain}/authorize`,
      token_endpoint: tokenEndpoint,
      jwks_uri: `https://${domain}/.well-known/jwks.json`,
      dpop_signing_alg_values_supported: ['ES256'],
    })
  )
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const proofClaims = (proof: string) => JSON.parse(Buffer.from(proof.split('.')[1]!, 'base64url').toString());

type Answer = 'nonce-then-ok' | 'nonce-always' | 'invalid-grant';

// Records the DPoP header of each token request. Without a proof carrying NONCE the server answers
// `use_dpop_nonce`, as a server that demands a nonce does.
function mockTokenEndpoint(answer: Answer) {
  const proofs: (string | null)[] = [];
  server.use(
    http.post(tokenEndpoint, ({ request }) => {
      const proof = request.headers.get('dpop');
      proofs.push(proof);
      if (answer === 'invalid-grant') {
        return HttpResponse.json({ error: 'invalid_grant', error_description: 'Invalid code' }, { status: 403 });
      }
      if (answer === 'nonce-always' || !proof || proofClaims(proof).nonce !== NONCE) {
        return HttpResponse.json(
          { error: 'use_dpop_nonce', error_description: 'Authorization server requires nonce in DPoP proof' },
          { status: 400, headers: { 'DPoP-Nonce': NONCE } }
        );
      }
      return HttpResponse.json({ access_token: '<dpop_access_token>', token_type: 'DPoP', expires_in: 3600 });
    })
  );
  return proofs;
}

const credential = {
  id: 'cred-id',
  rawId: 'cred-id',
  type: 'public-key' as const,
  authenticatorAttachment: 'platform' as const,
  response: { clientDataJSON: 'e30', authenticatorData: 'e30', signature: 'e30', userHandle: 'e30' },
};

type Grant = (authClient: AuthClient, fullResponse: boolean, requestOptions?: RequestOptions) => Promise<unknown>;

const grants: { name: string; run: Grant; error: new (...args: never[]) => Error; fullResponse: boolean[] }[] = [
  {
    name: 'passkey.getTokenByPasskey',
    run: (c, fullResponse, ro) =>
      c.passkey.getTokenByPasskey({ authSession: '<auth_session>', credential, ...(fullResponse && { fullResponse: true as const }) }, ro),
    error: PasskeyGetTokenError,
    fullResponse: [false, true],
  },
  {
    name: 'passwordless.getTokenByPasswordlessDbConnection',
    run: (c, fullResponse, ro) =>
      c.passwordless.getTokenByPasswordlessDbConnection(
        { authSession: '<auth_session>', otp: '123456', ...(fullResponse && { fullResponse: true as const }) },
        ro
      ),
    error: PasswordlessDbGetTokenError,
    fullResponse: [false, true],
  },
  {
    name: 'mfa.verify',
    run: (c, fullResponse, ro) =>
      c.mfa.verify({ mfaToken: '<mfa_token>', factorType: 'otp', otp: '123456', ...(fullResponse && { fullResponse: true as const }) }, ro),
    error: MfaVerifyError,
    fullResponse: [false, true],
  },
  {
    name: 'exchangeToken (custom token exchange)',
    run: (c, fullResponse, ro) =>
      c.exchangeToken(
        {
          subjectTokenType: 'urn:test:mcp-token',
          subjectToken: '<subject_token>',
          audience: 'https://api.example.com',
          ...(fullResponse && { fullResponse: true as const }),
        },
        ro
      ),
    error: TokenExchangeError,
    fullResponse: [false, true],
  },
  {
    name: 'getTokenForConnection (Token Vault)',
    run: (c, fullResponse, ro) =>
      c.getTokenForConnection(
        { connection: 'google-oauth2', refreshToken: '<refresh_token>', ...(fullResponse && { fullResponse: true as const }) },
        ro
      ),
    error: TokenForConnectionError,
    fullResponse: [false, true],
  },
  {
    name: 'backchannelAuthenticationGrant (CIBA)',
    run: (c, _fullResponse, ro) => c.backchannelAuthenticationGrant({ authReqId: '<auth_req_id>' }, ro),
    error: BackchannelAuthenticationError,
    fullResponse: [false],
  },
];

const cases = grants.flatMap((grant) => grant.fullResponse.map((fullResponse) => ({ ...grant, fullResponse })));

describe('DPoP nonce retry (use_dpop_nonce) on genericGrantRequest grants', () => {
  const newClient = () => new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>' });

  describe.each(cases)('$name (fullResponse: $fullResponse)', ({ run, error, fullResponse }) => {
    test('retries once with a proof carrying the server nonce and returns the tokens', async () => {
      const proofs = mockTokenEndpoint('nonce-then-ok');
      const dpopKeyPair = await oidcClient.randomDPoPKeyPair();

      const result = await run(newClient(), fullResponse, { dpopKeyPair });

      expect(proofs).toHaveLength(2);
      expect(proofClaims(proofs[0]!).nonce).toBeUndefined();
      expect(proofClaims(proofs[1]!).nonce).toBe(NONCE);
      if (fullResponse) {
        const { data, response } = result as { data: { accessToken: string }; response: Response };
        expect(data.accessToken).toBe('<dpop_access_token>');
        expect(response.status).toBe(200);
      } else {
        expect((result as { accessToken: string }).accessToken).toBe('<dpop_access_token>');
      }
    });

    test('throws the grant error after exactly two requests when the nonce is refused again', async () => {
      const proofs = mockTokenEndpoint('nonce-always');
      const dpopKeyPair = await oidcClient.randomDPoPKeyPair();

      await expect(run(newClient(), fullResponse, { dpopKeyPair })).rejects.toBeInstanceOf(error);
      expect(proofs).toHaveLength(2);
    });

    test('does not retry an error other than use_dpop_nonce', async () => {
      const proofs = mockTokenEndpoint('invalid-grant');
      const dpopKeyPair = await oidcClient.randomDPoPKeyPair();

      await expect(run(newClient(), fullResponse, { dpopKeyPair })).rejects.toBeInstanceOf(error);
      expect(proofs).toHaveLength(1);
    });

    test('does not retry without a dpopKeyPair', async () => {
      const proofs = mockTokenEndpoint('nonce-then-ok');

      await expect(run(newClient(), fullResponse)).rejects.toBeInstanceOf(error);
      expect(proofs).toEqual([null]);
    });
  });
});
