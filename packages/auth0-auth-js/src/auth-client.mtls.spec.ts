import { expect, test, afterAll, beforeAll, afterEach, describe } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AuthClient } from './auth-client.js';
import { NotSupportedError } from './errors.js';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

// Discovery is cached across clients, so every test gets its own domain.
let counter = 0;
const nextDomain = () => `mtls-${++counter}.auth0.local`;

interface Recorded {
  url: string;
  body: Record<string, unknown> | string;
}

/**
 * Mocks a tenant on `domain` whose mTLS endpoints live on `mtls.<domain>`. `withAlias` controls whether the
 * discovery document advertises `mtls_endpoint_aliases.token_endpoint`.
 */
const useTenant = (domain: string, withAlias: boolean) => {
  const plain = `https://${domain}`;
  const mtls = `https://mtls.${domain}`;
  const requests: Recorded[] = [];
  const record = async (request: Request) => {
    const text = await request.text();
    let body: Recorded['body'] = text;
    try {
      body = JSON.parse(text);
    } catch {
      // form-encoded body, kept as text
    }
    requests.push({ url: request.url, body });
  };
  const tokens = () =>
    HttpResponse.json({ access_token: '<access_token>', token_type: 'Bearer', expires_in: 3600 });
  const anonymousToken = () =>
    HttpResponse.json({
      access_token: '<anonymous_access_token>',
      session_token: '<session_token>',
      anon_transfer_token: '<transfer_token>',
      token_type: 'Bearer',
      expires_in: 3600,
    });

  server.use(
    http.get(`${plain}/.well-known/openid-configuration`, async ({ request }) => {
      await record(request);
      return HttpResponse.json({
        issuer: `${plain}/`,
        authorization_endpoint: `${plain}/authorize`,
        token_endpoint: `${plain}/oauth/token`,
        jwks_uri: `${plain}/.well-known/jwks.json`,
        ...(withAlias && { mtls_endpoint_aliases: { token_endpoint: `${mtls}/oauth/token` } }),
      });
    }),
    ...[plain, mtls].flatMap((origin) => [
      http.post(`${origin}/oauth/token`, async ({ request }) => (await record(request), tokens())),
      http.post(`${origin}/anonymous/token`, async ({ request }) => (await record(request), anonymousToken())),
      http.post(`${origin}/anonymous/logout`, async ({ request }) => (await record(request), new HttpResponse(null))),
    ])
  );
  return { plain, mtls, requests, urls: () => requests.map((r) => r.url) };
};

const makeClient = (domain: string, useMtls: boolean) =>
  new AuthClient({
    domain,
    clientId: '<client_id>',
    ...(useMtls ? { useMtls: true, customFetch: (...args: Parameters<typeof fetch>) => fetch(...args) } : {}),
    ...(!useMtls && { clientSecret: '<client_secret>' }),
  });

describe('mTLS token endpoint alias', () => {
  test('with useMtls, a token request goes to the alias', async () => {
    const domain = nextDomain();
    const tenant = useTenant(domain, true);

    await makeClient(domain, true).getTokenByRefreshToken({ refreshToken: '<refresh_token>' });

    expect(tenant.urls()).toEqual([`${tenant.plain}/.well-known/openid-configuration`, `${tenant.mtls}/oauth/token`]);
  });

  test('with useMtls and no alias, a token request throws before reaching the token endpoint', async () => {
    const domain = nextDomain();
    const tenant = useTenant(domain, false);
    const authClient = makeClient(domain, true);

    const call = () => authClient.getTokenByRefreshToken({ refreshToken: '<refresh_token>' });
    await expect(call()).rejects.toBeInstanceOf(NotSupportedError);
    // The discovery document is cached by now; the next call throws the same way.
    await expect(call()).rejects.toMatchObject({
      code: 'mtls_endpoint_aliases_missing',
      message: expect.stringContaining('mtls_endpoint_aliases.token_endpoint'),
    });

    expect(tenant.urls()).toEqual([`${tenant.plain}/.well-known/openid-configuration`]);
  });

  test.each([true, false])('without useMtls, a token request goes to the plain endpoint (alias advertised: %s)', async (withAlias) => {
    const domain = nextDomain();
    const tenant = useTenant(domain, withAlias);

    await makeClient(domain, false).getTokenByRefreshToken({ refreshToken: '<refresh_token>' });

    expect(tenant.urls()).toEqual([`${tenant.plain}/.well-known/openid-configuration`, `${tenant.plain}/oauth/token`]);
  });
});

describe('anonymous sessions under mTLS', () => {
  test('with useMtls, every anonymous request goes to the origin of the alias, without body-level client auth', async () => {
    const domain = nextDomain();
    const tenant = useTenant(domain, true);
    const { anonymous } = makeClient(domain, true);

    await anonymous.createSession();
    await anonymous.getAccessToken({ sessionToken: '<session_token>' });
    expect(await anonymous.mintTransferToken('<session_token>')).toBe('<transfer_token>');
    await anonymous.logout();

    const anonymousRequests = tenant.requests.filter((r) => r.url.includes('/anonymous/'));
    expect(anonymousRequests.map((r) => r.url)).toEqual([
      `${tenant.mtls}/anonymous/token`,
      `${tenant.mtls}/anonymous/token`,
      `${tenant.mtls}/anonymous/token`,
      `${tenant.mtls}/anonymous/logout`,
    ]);
    for (const { body } of anonymousRequests) {
      expect(body).toMatchObject({ client_id: '<client_id>' });
      expect(body).not.toHaveProperty('client_secret');
      expect(body).not.toHaveProperty('client_assertion');
    }
  });

  test('without useMtls, anonymous requests go to the plain domain and need no discovery', async () => {
    const domain = nextDomain();
    const tenant = useTenant(domain, true);
    const { anonymous } = makeClient(domain, false);

    await anonymous.createSession();
    await anonymous.logout();

    expect(tenant.urls()).toEqual([`${tenant.plain}/anonymous/token`, `${tenant.plain}/anonymous/logout`]);
  });

  test('with useMtls and no alias, anonymous requests are not sent', async () => {
    const domain = nextDomain();
    const tenant = useTenant(domain, false);
    const { anonymous } = makeClient(domain, true);

    await expect(anonymous.createSession()).rejects.toMatchObject({ code: 'mtls_endpoint_aliases_missing' });
    await expect(anonymous.getAccessToken({ sessionToken: '<session_token>' })).rejects.toMatchObject({
      code: 'mtls_endpoint_aliases_missing',
    });
    await expect(anonymous.logout()).rejects.toMatchObject({ code: 'mtls_endpoint_aliases_missing' });
    // The transfer ticket keeps its contract: `null` on any failure, so the login goes on without it.
    expect(await anonymous.mintTransferToken('<session_token>')).toBeNull();

    expect(tenant.urls().filter((url) => url.includes('/anonymous/'))).toEqual([]);
  });
});
