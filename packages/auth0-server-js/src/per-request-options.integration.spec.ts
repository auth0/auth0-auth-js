/**
 * Per-request options integration tests (Tier 1a: mock/MSW, no live tenant).
 * Multi-runtime scope: mechanics work across browser/Node/workers.
 *
 * Covers Group A checks from .forge/features/auth-separation/CHECK-MATRIX.md [#244].
 * Each test corresponds to a check ID (C-244-xx, C-236-xx).
 */

import { expect, describe, it, beforeAll, afterAll, afterEach } from 'vitest';
import { ServerClient } from './server-client.js';
import { generateToken } from './test-utils/tokens.js';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import type { TokenSet, ConnectionTokenSet } from './types.js';

const domain = 'per-request.local';
let accessToken: string;

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: `https://${domain}/`,
      authorization_endpoint: `https://${domain}/authorize`,
      backchannel_authentication_endpoint: `https://${domain}/bc-authorize`,
      token_endpoint: `https://${domain}/oauth/token`,
      revocation_endpoint: `https://${domain}/oauth/revoke`,
    });
  }),
  http.post(`https://${domain}/bc-authorize`, async () => {
    return HttpResponse.json({
      auth_req_id: 'auth_req_bc_123',
      interval: 0.5,
      expires_in: 60,
    });
  }),
  http.post(`https://${domain}/oauth/token`, async () => {
    return HttpResponse.json({
      access_token: accessToken,
      id_token: await generateToken(domain, 'user_123', '<client_id>'),
      expires_in: 60,
      token_type: 'Bearer',
      scope: 'openid profile email offline_access',
      refresh_token: '<refresh_token>',
    });
  }),
  http.post(`https://${domain}/oauth/revoke`, async ({ request }) => {
    // C-244-03: capture headers to verify requestOptions propagated
    const customHeader = request.headers.get('x-custom-revoke-header');
    if (customHeader === 'C-244-03-marker') {
      // Signal that requestOptions was seen by the revoke endpoint
      return new HttpResponse(null, { status: 200, headers: { 'x-saw-custom-header': 'true' } });
    }
    return new HttpResponse(null, { status: 200 });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

beforeAll(async () => {
  accessToken = await generateToken(domain, 'user_123');
});

afterEach(() => {
  server.resetHandlers();
});

describe('per-request options mechanics - ServerClient (Tier 1a) [#244]', () => {
  // C-244-01..05 removed: these were placeholder it.skip stubs for a prior
  // branch that lacked requestOptions signatures. Those signatures now exist and
  // the delegation/forwarding behavior is covered by server-client.spec.ts
  // (A1-A10). Keeping empty stubs signalled false coverage.

  // Type-level checks for C-236-01, C-236-05, C-236-06
  it('C-236-01: TokenSet and ConnectionTokenSet do NOT have httpResponse; only auth-js SessionTransferTokenResult does', () => {
    // server-js TokenSet/ConnectionTokenSet are defined in src/types.ts L103-116.
    // They do NOT have httpResponse.
    const tokenSet: TokenSet = {
      audience: 'default',
      accessToken: '<access_token>',
      scope: 'openid',
      expiresAt: 0,
    };
    const connectionTokenSet: ConnectionTokenSet = {
      accessToken: '<access_token>',
      scope: 'openid',
      expiresAt: 0,
      connection: 'google-oauth2',
    };

    // @ts-expect-error - TokenSet should NOT have httpResponse
    void tokenSet.httpResponse;
    // @ts-expect-error - ConnectionTokenSet should NOT have httpResponse
    void connectionTokenSet.httpResponse;

    // Note: SessionTransferTokenResult is an auth0-auth-js type, not server-js.
    // server-js does NOT expose session-transfer-token methods (those are auth-js only).
    // This check is satisfied by the fact that the types above do NOT compile with httpResponse.
    expect(true).toBe(true);
  });

  it('C-236-05: session-establishment methods return types WITHOUT httpResponse', () => {
    // Methods: completeInteractiveLogin, loginBackchannel, completePasswordless, loginWithCustomTokenExchange
    // Their return types (per src/types.ts):
    // - completeInteractiveLogin → { appState?, authorizationDetails? }
    // - loginBackchannel → LoginBackchannelResult { authorizationDetails? }
    // - completePasswordless → CompletePasswordlessResult { authorizationDetails? }
    // - loginWithCustomTokenExchange → LoginWithCustomTokenExchangeResult { authorizationDetails? }
    // None have httpResponse.

    type AssertNoHttpResponse<T> = 'httpResponse' extends keyof T ? false : true;

    // Infer return types (unwrap Promises)
    type CompleteInteractiveLoginResult = Awaited<ReturnType<ServerClient['completeInteractiveLogin']>>;
    type LoginBackchannelResult = Awaited<ReturnType<ServerClient['loginBackchannel']>>;
    type CompletePasswordlessResult = Awaited<ReturnType<ServerClient['completePasswordless']>>;
    type LoginWithCustomTokenExchangeResult = Awaited<ReturnType<ServerClient['loginWithCustomTokenExchange']>>;

    const _check1: AssertNoHttpResponse<CompleteInteractiveLoginResult> = true;
    const _check2: AssertNoHttpResponse<LoginBackchannelResult> = true;
    const _check3: AssertNoHttpResponse<CompletePasswordlessResult> = true;
    const _check4: AssertNoHttpResponse<LoginWithCustomTokenExchangeResult> = true;

    expect(_check1 && _check2 && _check3 && _check4).toBe(true);
  });

  it('C-236-06: revokeRefreshToken (void) and changePassword (string) carry no success metadata', () => {
    // revokeRefreshToken returns Promise<void> (src/server-client.ts L1096)
    // changePassword is on `client.database.changePassword()` (src/database/server-database-client.ts),
    // returns Promise<string> (the password reset email confirmation text).
    // Neither returns httpResponse or metadata.

    type RevokeResult = Awaited<ReturnType<ServerClient['revokeRefreshToken']>>;
    type ChangePasswordResult = Awaited<ReturnType<ServerClient['database']['changePassword']>>;

    // revokeRefreshToken → void
    const _check1: RevokeResult extends void ? true : false = true;
    // changePassword → string (no metadata object)
    const _check2: ChangePasswordResult extends string ? true : false = true;

    expect(_check1 && _check2).toBe(true);
  });
});
