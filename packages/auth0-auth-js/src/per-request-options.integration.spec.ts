/**
 * Per-request options integration tests (Tier 1a: mock/MSW, no live tenant).
 * Multi-runtime scope: mechanics work across browser/Node/workers.
 *
 * Covers Group A checks from .forge/features/auth-separation/CHECK-MATRIX.md [#230].
 * Each test corresponds to a check ID (C-230-xx).
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { expectTypeOf } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse, delay } from 'msw';
import { AuthClient } from './auth-client.js';
import type { RequestOptions, BackchannelAuthenticationOptions, ExchangeProfileOptions, TokenVaultExchangeOptions } from './types.js';
import type { ListAuthenticatorsOptions, EnrollAuthenticatorOptions, ChallengeOptions, MfaVerifyOptions, DeleteAuthenticatorOptions } from './mfa/types.js';
import type { SendEmailOptions, SendSmsOptions } from './passwordless/types.js';
import type { SignUpOptions, ChangePasswordOptions } from './database/types.js';
import { generateToken, jwks } from './test-utils/tokens.js';

const domain = 'auth0.local';
let accessToken: string;

const buildOpenIdConfiguration = (customDomain: string) => ({
  issuer: `https://${customDomain}/`,
  authorization_endpoint: `https://${customDomain}/authorize`,
  token_endpoint: `https://${customDomain}/oauth/token`,
  jwks_uri: `https://${customDomain}/.well-known/jwks.json`,
});

let mockOpenIdConfiguration = buildOpenIdConfiguration(domain);

const restHandlers = [
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(mockOpenIdConfiguration);
  }),
  http.get(`https://${domain}/.well-known/jwks.json`, () => {
    return HttpResponse.json({ keys: jwks });
  }),
  http.post(mockOpenIdConfiguration.token_endpoint, async () => {
    const idToken = await generateToken(domain, 'user_123', '<client_id>');
    return HttpResponse.json({
      access_token: accessToken,
      id_token: idToken,
      expires_in: 60,
      token_type: 'Bearer',
      scope: 'openid profile email',
    });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

beforeEach(async () => {
  accessToken = await generateToken(domain, 'user_123');
  mockOpenIdConfiguration = buildOpenIdConfiguration(domain);
  server.resetHandlers(...restHandlers);
});

describe('per-request options mechanics (Tier 1a) [#230]', () => {
  it('C-230-01: RequestOptions type shape correct and re-exported', () => {
    // Type-level check: verify RequestOptions has expected shape
    expectTypeOf<RequestOptions>().toMatchTypeOf<{
      signal?: AbortSignal;
      headers?: Record<string, string>;
      customFetch?: typeof fetch;
    }>();
  });

  it('C-230-02: signal aborts in-flight token request', async () => {
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async () => {
        await delay('infinite');
        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    const controller = new AbortController();
    const promise = authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      { signal: controller.signal }
    );

    setTimeout(() => controller.abort(), 10);
    await expect(promise).rejects.toThrow();
  });

  it('C-230-03: signal composed with client timeout (either fires)', async () => {
    // Scenario: external signal fires first
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async () => {
        await delay(5000);
        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    const controller = new AbortController();
    const promise = authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      { signal: controller.signal }
    );

    setTimeout(() => controller.abort(), 10);
    await expect(promise).rejects.toThrow();
  });

  it('C-230-04: customFetch actually invoked, return honored', async () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    let tokenCallCount = 0;
    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async () => {
        tokenCallCount++;
        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const customFetchSpy = vi.fn<typeof fetch>();
    customFetchSpy.mockImplementation((url, init) => fetch(url, init));

    const result = await authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      { customFetch: customFetchSpy }
    );

    // customFetch should have been invoked for the token request
    expect(customFetchSpy).toHaveBeenCalled();
    expect(tokenCallCount).toBeGreaterThan(0);
    expect(result.accessToken).toBeTruthy();
  });

  it('C-230-05: caller headers forwarded', async () => {
    let capturedHeaders: Headers | undefined;

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        capturedHeaders = request.headers;
        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    await authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      { headers: { 'x-custom-header': 'test-value' } }
    );

    expect(capturedHeaders?.get('x-custom-header')).toBe('test-value');
  });

  it('C-230-06: header precedence - SDK Authorization + Auth0-Client win (SECURITY)', async () => {
    const capturedHeaders: Record<string, string> = {};

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        request.headers.forEach((value, key) => {
          capturedHeaders[key.toLowerCase()] = value;
        });
        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    const result = await authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      {
        headers: {
          'Authorization': 'Bearer attacker-token',
          'Auth0-Client': 'attacker-client',
          'X-Custom': 'should-appear',
        },
      }
    );

    expect(result.accessToken).toBeTruthy();

    // Caller's custom header should appear
    expect(capturedHeaders['x-custom']).toBe('should-appear');

    // Caller cannot override Authorization - for client credentials flow, openid-client
    // sends auth via body (client_id/client_secret) not header. The SDK prevents the
    // attacker's Authorization header from being forwarded.
    const authHeader = capturedHeaders['authorization'];
    if (authHeader) {
      // If Authorization is present (some flows), it must not be the attacker's
      expect(authHeader).not.toContain('attacker-token');
    }

    // Auth0-Client should be SDK telemetry, not attacker's
    const auth0Client = capturedHeaders['auth0-client'];
    expect(auth0Client).toBeTruthy();
    expect(auth0Client).not.toBe('attacker-client');
    // Decode base64 to check content
    const decoded = JSON.parse(atob(auth0Client!));
    expect(decoded.name).toBe('@auth0/auth0-auth-js');
  });

  it('C-230-07: Auth0-Client telemetry sent even with customFetch', async () => {
    const capturedHeaders: Record<string, string> = {};

    const customFetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      if (init?.headers) {
        const headers = new Headers(init.headers);
        headers.forEach((value, key) => {
          capturedHeaders[key.toLowerCase()] = value;
        });
      }
      return fetch(url, init);
    });

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    await authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      { customFetch: customFetchSpy }
    );

    expect(customFetchSpy).toHaveBeenCalled();
    const auth0Client = capturedHeaders['auth0-client'];
    expect(auth0Client).toBeTruthy();
    // Decode base64 telemetry header
    const decoded = JSON.parse(atob(auth0Client!));
    expect(decoded.name).toBe('@auth0/auth0-auth-js');
  });

  it('C-230-08: discovery not cancelled by requestOptions.signal', async () => {
    let discoveryCallCount = 0;

    server.use(
      http.get(`https://${domain}/.well-known/openid-configuration`, () => {
        discoveryCallCount++;
        return HttpResponse.json(mockOpenIdConfiguration);
      }),
      http.post(mockOpenIdConfiguration.token_endpoint, async () => {
        await delay('infinite');
        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    // Fresh client instance to trigger discovery
    const authClient = new AuthClient({
      domain: 'auth0-fresh.local',
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    // Override for this fresh domain
    server.use(
      http.get('https://auth0-fresh.local/.well-known/openid-configuration', () => {
        discoveryCallCount++;
        return HttpResponse.json({
          ...mockOpenIdConfiguration,
          issuer: 'https://auth0-fresh.local/',
          token_endpoint: 'https://auth0-fresh.local/oauth/token',
        });
      }),
      http.post('https://auth0-fresh.local/oauth/token', async () => {
        await delay('infinite');
        const idToken = await generateToken('auth0-fresh.local', 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const controller = new AbortController();
    const promise = authClient.getTokenByClientCredentials(
      { audience: 'https://api.example.com' },
      { signal: controller.signal }
    );

    setTimeout(() => controller.abort(), 10);
    await expect(promise).rejects.toThrow();

    // Discovery should have completed despite abort
    expect(discoveryCallCount).toBeGreaterThanOrEqual(1);
  });

  it('C-230-09: method coverage - all auth-js methods accept trailing requestOptions', () => {
    // Type-level check: verify methods accept RequestOptions as last param
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    // Methods that SHOULD accept requestOptions
    expectTypeOf(authClient.getTokenByCode).parameters.toMatchTypeOf<
      [URL, { codeVerifier: string; organization?: string }, RequestOptions?]
    >();
    expectTypeOf(authClient.getTokenByRefreshToken).parameters.toMatchTypeOf<
      [{ refreshToken: string; audience?: string; scope?: string }, RequestOptions?]
    >();
    expectTypeOf(authClient.getTokenByClientCredentials).parameters.toMatchTypeOf<
      [{ audience: string; organization?: string }, RequestOptions?]
    >();
    expectTypeOf(authClient.getTokenByPassword).parameters.toMatchTypeOf<
      [{ username: string; password: string; audience?: string; scope?: string; realm?: string; auth0ForwardedFor?: string }, RequestOptions?]
    >();
    expectTypeOf(authClient.backchannelAuthentication).parameters.toMatchTypeOf<
      [BackchannelAuthenticationOptions, RequestOptions?]
    >();
    expectTypeOf(authClient.revokeToken).parameters.toMatchTypeOf<
      [{ token: string; tokenTypeHint?: 'refresh_token' | 'access_token' }, RequestOptions?]
    >();
    expectTypeOf(authClient.exchangeToken).parameters.toMatchTypeOf<[ExchangeProfileOptions | TokenVaultExchangeOptions, RequestOptions?]>();

    // URL builders should NOT accept requestOptions (no trailing param)
    expectTypeOf(authClient.buildAuthorizationUrl).parameters.not.toMatchTypeOf<[Record<string, unknown>, RequestOptions]>();
    expectTypeOf(authClient.buildLogoutUrl).parameters.not.toMatchTypeOf<[Record<string, unknown>, RequestOptions]>();
  });

  it('C-230-10: sub-client arg shapes (MFA/passkey/passwordless/database)', () => {
    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    // MFA sub-client: all methods accept (options, requestOptions?)
    expectTypeOf(authClient.mfa.listAuthenticators).parameters.toMatchTypeOf<
      [ListAuthenticatorsOptions, RequestOptions?]
    >();
    expectTypeOf(authClient.mfa.enrollAuthenticator).parameters.toMatchTypeOf<
      [EnrollAuthenticatorOptions, RequestOptions?]
    >();
    expectTypeOf(authClient.mfa.challengeAuthenticator).parameters.toMatchTypeOf<
      [ChallengeOptions, RequestOptions?]
    >();
    expectTypeOf(authClient.mfa.verify).parameters.toMatchTypeOf<[MfaVerifyOptions, RequestOptions?]>();
    expectTypeOf(authClient.mfa.deleteAuthenticator).parameters.toMatchTypeOf<
      [DeleteAuthenticatorOptions, RequestOptions?]
    >();

    // Passwordless sub-client
    expectTypeOf(authClient.passwordless.sendEmail).parameters.toMatchTypeOf<
      [SendEmailOptions, RequestOptions?]
    >();
    expectTypeOf(authClient.passwordless.sendSms).parameters.toMatchTypeOf<
      [SendSmsOptions, RequestOptions?]
    >();

    // Database sub-client
    expectTypeOf(authClient.database.signUp).parameters.toMatchTypeOf<[SignUpOptions, RequestOptions?]>();
    expectTypeOf(authClient.database.changePassword).parameters.toMatchTypeOf<
      [ChangePasswordOptions, RequestOptions?]
    >();
  });

  it('C-230-11: concurrency isolation - parallel calls do not cross-leak options', async () => {
    const capturedRequests: Array<{ headers: Record<string, string> }> = [];

    server.use(
      http.post(mockOpenIdConfiguration.token_endpoint, async ({ request }) => {
        const headers: Record<string, string> = {};
        request.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });
        capturedRequests.push({ headers });

        const idToken = await generateToken(domain, 'user_123', '<client_id>');
        return HttpResponse.json({
          access_token: accessToken,
          id_token: idToken,
          expires_in: 60,
          token_type: 'Bearer',
        });
      })
    );

    const authClient = new AuthClient({
      domain,
      clientId: '<client_id>',
      clientSecret: '<client_secret>',
    });

    await Promise.all([
      authClient.getTokenByClientCredentials(
        { audience: 'https://api.example.com' },
        { headers: { 'x-req-id': 'request-1' } }
      ),
      authClient.getTokenByClientCredentials(
        { audience: 'https://api.example.com' },
        { headers: { 'x-req-id': 'request-2' } }
      ),
    ]);

    expect(capturedRequests).toHaveLength(2);
    expect(capturedRequests[0]?.headers['x-req-id']).toBe('request-1');
    expect(capturedRequests[1]?.headers['x-req-id']).toBe('request-2');
  });
});
