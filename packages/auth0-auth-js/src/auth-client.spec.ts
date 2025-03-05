import { expect, test, afterAll, beforeAll, beforeEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AuthClient } from './auth-client.js';

import { generateToken } from './test-utils/tokens.js';

const domain = 'auth0.local';
let accessToken: string;
const mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  backchannel_authentication_endpoint: `https://${domain}/custom-authorize`,
  token_endpoint: `https://${domain}/custom/token`,
  end_session_endpoint: `https://${domain}/logout`,
  pushed_authorization_request_endpoint: `https://${domain}/pushed-authorize`,
};

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.post(
    mockOpenIdConfiguration.backchannel_authentication_endpoint,
    async () => {
      const auth_req_id = 'auth_req_123';

      return HttpResponse.json({
        auth_req_id: auth_req_id,
        interval: 0.5,
        expires_in: 60,
      });
    }
  ),
  http.post(mockOpenIdConfiguration.token_endpoint, async () => {
    return HttpResponse.json({
      access_token: accessToken,
      id_token: await generateToken(domain, 'user_123', '<client_id>'),
      expires_in: 60,
      token_type: 'Bearer',
      scope: '<scope>',
    });
  }),
  http.post(
    mockOpenIdConfiguration.pushed_authorization_request_endpoint,
    () => {
      return HttpResponse.json(
        {
          request_uri: 'request_uri_123',
          expires_in: 60,
        },
        { status: 201 }
      );
    }
  ),
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));

// Close server after all tests
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
});

test('configuration - should use customFetch', async () => {
  const mockFetch = vi.fn().mockImplementation(fetch);
  const authClient = new AuthClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    customFetch: mockFetch,
  });

  await authClient.buildAuthorizationUrl();

  expect(mockFetch).toHaveBeenCalledTimes(1);

  mockFetch.mockClear();

  const tokenResponse = await authClient.getTokenByCode(
    new URL(`https://${domain}?code=123`),
    {
      codeVerifier: '123',
    }
  );

  expect(tokenResponse.accessToken).toBe(accessToken);
  expect(mockFetch).toHaveBeenCalledTimes(1);
});
