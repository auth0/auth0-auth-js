import { expect, test, afterAll, beforeAll, afterEach, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AuthClient } from './auth-client.js';
import { DomainValidationError } from './errors.js';
import { resolveAuthorizationServer } from './authorization-server.js';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

/** Mocks an authorization server whose issuer is `issuer` and whose endpoints live under `origin`. */
const useAuthorizationServer = (origin: string, issuer: string, discoveryUrl: string) => {
  const requests: string[] = [];
  const record = (request: Request) => requests.push(`${request.method} ${request.url}`);
  server.use(
    http.get(discoveryUrl, ({ request }) => {
      record(request);
      return HttpResponse.json({
        issuer,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/oauth/token`,
        revocation_endpoint: `${origin}/oauth/revoke`,
        jwks_uri: `${origin}/.well-known/jwks.json`,
      });
    }),
    http.post(`${origin}/oauth/token`, ({ request }) => {
      record(request);
      return HttpResponse.json({ access_token: '<access_token>', token_type: 'Bearer', expires_in: 3600 });
    }),
    http.post(`${origin}/oauth/revoke`, ({ request }) => {
      record(request);
      return new HttpResponse(null, { status: 200 });
    }),
    http.get(`${origin}/mfa/authenticators`, ({ request }) => {
      record(request);
      return HttpResponse.json([]);
    })
  );
  return requests;
};

const makeClient = (domain: string, allowInsecureRequests?: boolean) =>
  new AuthClient({ domain, clientId: '<client_id>', clientSecret: '<client_secret>', allowInsecureRequests });

describe('resolveAuthorizationServer', () => {
  test('a bare host is used as today', () => {
    const resolved = resolveAuthorizationServer('Example.auth0.com');
    expect(resolved.baseUrl).toBe('https://Example.auth0.com');
    expect(resolved.issuer.href).toBe('https://example.auth0.com/');
    expect(resolved.cacheKey).toBe('example.auth0.com');
    expect(resolveAuthorizationServer('localhost:3000').baseUrl).toBe('https://localhost:3000');
  });

  test.each(['https://example.auth0.com', 'https://example.auth0.com/', 'https://EXAMPLE.auth0.com'])(
    'a root URL (%s) gets a trailing slash',
    (domain) => {
      const resolved = resolveAuthorizationServer(domain);
      expect(resolved.baseUrl).toBe('https://example.auth0.com');
      expect(resolved.issuer.href).toBe('https://example.auth0.com/');
    }
  );

  test('a path issuer is kept as given, and its base URL is the origin', () => {
    const resolved = resolveAuthorizationServer('https://myorg.okta.com/oauth2/default');
    expect(resolved.issuer.href).toBe('https://myorg.okta.com/oauth2/default');
    expect(resolved.baseUrl).toBe('https://myorg.okta.com');
  });

  test('a port is kept', () => {
    expect(resolveAuthorizationServer('https://example.auth0.com:8443').issuer.href).toBe('https://example.auth0.com:8443/');
  });

  test('http requires allowInsecureRequests', () => {
    expect(() => resolveAuthorizationServer('http://localhost:3000')).toThrow(DomainValidationError);
    const resolved = resolveAuthorizationServer('http://localhost:3000', true);
    expect(resolved.baseUrl).toBe('http://localhost:3000');
    expect(resolved.issuer.href).toBe('http://localhost:3000/');
  });

  test.each([
    ['a query', 'https://example.auth0.com/?a=1'],
    ['a fragment', 'https://example.auth0.com/#a'],
    ['credentials', 'https://user:pass@example.auth0.com'],
    ['another scheme', 'ftp://example.auth0.com'],
    ['no host', 'https://'],
  ])('a URL with %s is refused', (_label, domain) => {
    expect(() => resolveAuthorizationServer(domain, true)).toThrow(DomainValidationError);
  });

  test('the error has a code', () => {
    expect(() => resolveAuthorizationServer('http://localhost:3000')).toThrow(
      expect.objectContaining({ name: 'DomainValidationError', code: 'domain_validation_error' })
    );
  });
});

describe('AuthClient with an issuer URL', () => {
  test('http without allowInsecureRequests throws in the constructor, before any request', () => {
    expect(() => makeClient('http://localhost:3000')).toThrow(DomainValidationError);
  });

  test('a path issuer is discovered under its path and its issuer is accepted', async () => {
    const issuer = 'https://myorg.okta.test/oauth2/default';
    const requests = useAuthorizationServer(
      'https://myorg.okta.test',
      issuer,
      `${issuer}/.well-known/openid-configuration`
    );

    const { authorizationUrl } = await makeClient(issuer).buildAuthorizationUrl({
      authorizationParams: { redirect_uri: 'https://app.test/callback' },
    });

    expect(authorizationUrl.origin + authorizationUrl.pathname).toBe('https://myorg.okta.test/authorize');
    expect(requests).toEqual([`GET ${issuer}/.well-known/openid-configuration`]);
  });

  test('http://localhost with allowInsecureRequests works end to end', async () => {
    const origin = 'http://localhost:3000';
    const requests = useAuthorizationServer(origin, `${origin}/`, `${origin}/.well-known/openid-configuration`);
    const authClient = makeClient(origin, true);

    const { authorizationUrl } = await authClient.buildAuthorizationUrl({
      authorizationParams: { redirect_uri: 'http://localhost:4000/callback' },
    });
    const tokens = await authClient.getTokenByRefreshToken({ refreshToken: '<refresh_token>' });
    await authClient.revokeToken({ token: '<refresh_token>' });
    const logoutUrl = await authClient.buildLogoutUrl({ returnTo: 'http://localhost:4000' });
    await authClient.mfa.listAuthenticators({ mfaToken: '<mfa_token>' });

    expect(authorizationUrl.origin).toBe(origin);
    expect(tokens.accessToken).toBe('<access_token>');
    expect(logoutUrl.origin + logoutUrl.pathname).toBe(`${origin}/v2/logout`);
    expect(requests).toEqual([
      `GET ${origin}/.well-known/openid-configuration`,
      `POST ${origin}/oauth/token`,
      `POST ${origin}/oauth/revoke`,
      `GET ${origin}/mfa/authenticators`,
    ]);
  });
});
