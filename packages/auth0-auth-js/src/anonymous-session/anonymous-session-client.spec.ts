import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { AnonymousSessionClient } from './anonymous-session-client.js';
import { AnonymousSessionError } from './errors.js';

const exportPrivateKeyToPem = async (privateKey: CryptoKey): Promise<string> => {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  const keyBase64 = Buffer.from(pkcs8).toString('base64');
  const keyLines = keyBase64.match(/.{1,64}/g) ?? [keyBase64];
  return `-----BEGIN PRIVATE KEY-----\n${keyLines.join('\n')}\n-----END PRIVATE KEY-----`;
};

const generateRsaKeyPair = () =>
  crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: { name: 'SHA-256' } },
    true,
    ['sign', 'verify']
  ) as Promise<CryptoKeyPair>;

const domain = 'auth0.local';
const clientId = 'test-client-id';
const sessionToken = 'test-session-token';
const accessToken = 'test-access-token';
const sessionExpiresIn = 2592000; // 30 days in seconds

const makeClient = (overrides?: Partial<ConstructorParameters<typeof AnonymousSessionClient>[0]>) =>
  new AnonymousSessionClient({ domain, clientId, ...overrides });

// ─── MSW server ──────────────────────────────────────────────────────────────

const restHandlers = [
  http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;

    // Simulate session_expired when a known expired token is passed
    if (body.session_token === 'expired-session-token') {
      return HttpResponse.json(
        { error: 'session_expired', error_description: 'The session has expired' },
        { status: 400 }
      );
    }

    // Simulate invalid_session_token
    if (body.session_token === 'invalid-session-token') {
      return HttpResponse.json(
        { error: 'invalid_session_token', error_description: 'The session token is invalid' },
        { status: 400 }
      );
    }

    // Simulate feature_not_enabled
    if (body.client_id === 'disabled-client') {
      return HttpResponse.json(
        { error: 'feature_not_enabled', error_description: 'Anonymous sessions are not enabled for this tenant' },
        { status: 403 }
      );
    }

    // Simulate metadata size error — platform returns invalid_request, not metadata_too_large
    if (body.metadata && JSON.stringify(body.metadata).length > 1024) {
      return HttpResponse.json(
        { error: 'invalid_request', error_description: 'metadata exceeds the maximum allowed size' },
        { status: 400 }
      );
    }

    // Re-mint: session_token present → return only access_token (no session_token in response)
    if (body.session_token) {
      return HttpResponse.json({
        access_token: 'renewed-access-token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: body.scope ?? 'openid',
        session_expires_in: sessionExpiresIn - 3600, // counts down, not reset
      });
    }

    // Create: no session_token → return both tokens
    return HttpResponse.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: body.scope ?? 'openid',
      session_token: sessionToken,
      session_expires_in: sessionExpiresIn,
    });
  }),

  http.post(`https://${domain}/anonymous/logout`, () => {
    return new HttpResponse(null, { status: 204 });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// ─── createSession ────────────────────────────────────────────────────────────

describe('createSession', () => {
  test('creates a new anonymous session and returns session + access token', async () => {
    const client = makeClient();
    const session = await client.createSession();

    expect(session.sessionToken).toBe(sessionToken);
    expect(session.accessToken).toBe(accessToken);
    expect(session.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test('sends audience and scope when provided', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient();
    await client.createSession({ audience: 'https://api.example.com', scope: 'openid profile' });

    expect(capturedBody.audience).toBe('https://api.example.com');
    expect(capturedBody.scope).toBe('openid profile');
    expect(capturedBody.client_id).toBe(clientId);
  });

  test('sends metadata when provided', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient();
    await client.createSession({ metadata: { source: 'landing-page', referral: 'newsletter' } });

    expect(capturedBody.metadata).toEqual({ source: 'landing-page', referral: 'newsletter' });
  });

  test('does not include session_token in the request body', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient();
    await client.createSession();

    expect(capturedBody.session_token).toBeUndefined();
  });

  test('sends request with credentials: include', async () => {
    const spy = vi.fn((...args: Parameters<typeof fetch>) => fetch(...args));
    const client = makeClient({ customFetch: spy });
    await client.createSession();
    expect(spy.mock.calls[0]![1]).toMatchObject({ credentials: 'include' });
  });

  test('throws AnonymousSessionError when feature is not enabled', async () => {
    const client = new AnonymousSessionClient({ domain, clientId: 'disabled-client' });

    await expect(client.createSession()).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'feature_not_enabled',
    });
  });

  test('throws AnonymousSessionError with cause when API returns an error', async () => {
    const client = new AnonymousSessionClient({ domain, clientId: 'disabled-client' });

    const error = await client.createSession().catch((e) => e);

    expect(error).toBeInstanceOf(AnonymousSessionError);
    expect(error.cause).toMatchObject({
      error: 'feature_not_enabled',
      error_description: expect.any(String),
    });
  });

  test('throws AnonymousSessionError when server returns non-JSON error', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        new HttpResponse('Internal Server Error', { status: 500, headers: { 'Content-Type': 'text/plain' } })
      )
    );

    const client = makeClient();
    const error = await client.createSession().catch((e) => e);

    expect(error).toBeInstanceOf(AnonymousSessionError);
    expect(error.code).toBe('server_error');
  });

  test('throws AnonymousSessionError when session_token is missing from response', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          // session_token intentionally omitted
        })
      )
    );

    const client = makeClient();
    await expect(client.createSession()).rejects.toMatchObject({
      code: 'server_error',
    });
  });

  test('throws AnonymousSessionError when access_token is missing from response', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        HttpResponse.json({
          // access_token intentionally omitted
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
        })
      )
    );

    const client = makeClient();
    await expect(client.createSession()).rejects.toMatchObject({
      code: 'server_error',
    });
  });

  test('throws AnonymousSessionError when expires_in is missing from response', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          // expires_in intentionally omitted
          session_token: sessionToken,
        })
      )
    );

    const client = makeClient();
    await expect(client.createSession()).rejects.toMatchObject({
      code: 'server_error',
    });
  });

  test('throws AnonymousSessionError with code invalid_request when metadata exceeds 1 KB', async () => {
    const client = makeClient();
    const largeMetadata = { data: 'x'.repeat(1025) };

    await expect(client.createSession({ metadata: largeMetadata })).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'invalid_request',
    });
  });
});

// ─── getTokenSilently ─────────────────────────────────────────────────────────

describe('getTokenSilently', () => {
  test('creates a new session when no sessionToken is provided', async () => {
    const client = makeClient();
    const session = await client.getTokenSilently();

    expect(session.sessionToken).toBe(sessionToken);
    expect(session.accessToken).toBe(accessToken);
  });

  test('re-mints access token when sessionToken is provided', async () => {
    const client = makeClient();
    const session = await client.getTokenSilently({ sessionToken });

    expect(session.accessToken).toBe('renewed-access-token');
    expect(session.sessionToken).toBe(sessionToken);
    expect(session.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test('sends sessionToken, audience and scope in the request body', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: 'renewed-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient();
    await client.getTokenSilently({ sessionToken: 'my-session-token', audience: 'https://api.example.com', scope: 'openid' });

    expect(capturedBody.session_token).toBe('my-session-token');
    expect(capturedBody.audience).toBe('https://api.example.com');
    expect(capturedBody.scope).toBe('openid');
    expect(capturedBody.client_id).toBe(clientId);
  });

  test('passes audience and scope through when creating a new session', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient();
    await client.getTokenSilently({ audience: 'https://api.example.com', scope: 'openid' });

    expect(capturedBody.audience).toBe('https://api.example.com');
    expect(capturedBody.scope).toBe('openid');
    expect(capturedBody.session_token).toBeUndefined();
  });

  test('silently creates a new session when session_expired is encountered', async () => {
    const client = makeClient();
    const result = await client.getTokenSilently({ sessionToken: 'expired-session-token' });

    expect(result.sessionToken).toBe(sessionToken);
    expect(result.accessToken).toBe(accessToken);
  });

  test('silently creates a new session when invalid_session_token is encountered', async () => {
    const client = makeClient();
    const result = await client.getTokenSilently({ sessionToken: 'invalid-session-token' });

    expect(result.sessionToken).toBe(sessionToken);
    expect(result.accessToken).toBe(accessToken);
  });

  test('propagates non-session errors to the caller', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        HttpResponse.json(
          { error: 'invalid_scope', error_description: 'Requested scope not allowed' },
          { status: 400 }
        )
      )
    );

    const client = makeClient();
    await expect(client.getTokenSilently({ sessionToken })).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'invalid_scope',
    });
  });
});

// ─── logout ───────────────────────────────────────────────────────────────────

describe('logout', () => {
  test('ends the anonymous session', async () => {
    const client = makeClient();
    await expect(client.logout()).resolves.toBeUndefined();
  });

  test('sends client_id in the request body', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/logout`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return new HttpResponse(null, { status: 204 });
      })
    );

    const client = makeClient();
    await client.logout();

    expect(capturedBody.client_id).toBe(clientId);
    expect(capturedBody.session_token).toBeUndefined();
  });

  test('throws AnonymousSessionError when server returns an error', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/logout`, () =>
        HttpResponse.json(
          { error: 'invalid_session_token', error_description: 'Session token not found' },
          { status: 400 }
        )
      )
    );

    const client = makeClient();
    await expect(client.logout()).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'invalid_session_token',
    });
  });

  test('throws AnonymousSessionError when server returns non-JSON error on logout', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/logout`, () =>
        new HttpResponse('Service Unavailable', { status: 503, headers: { 'Content-Type': 'text/plain' } })
      )
    );

    const client = makeClient();
    const error = await client.logout().catch((e) => e);

    expect(error).toBeInstanceOf(AnonymousSessionError);
    expect(error.code).toBe('server_error');
  });
});

// ─── expiresAt calculation ────────────────────────────────────────────────────

describe('expiresAt', () => {
  test('sets expiresAt to approximately now + expires_in seconds', async () => {
    const client = makeClient();
    const before = Math.floor(Date.now() / 1000);
    const session = await client.createSession();
    const after = Math.floor(Date.now() / 1000);

    // expires_in is 3600 in the mock
    expect(session.expiresAt).toBeGreaterThanOrEqual(before + 3600);
    expect(session.expiresAt).toBeLessThanOrEqual(after + 3600);
  });
});

// ─── client authentication ────────────────────────────────────────────────────

describe('client authentication', () => {
  test('sends client_secret when clientSecret is configured', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient({ clientSecret: 'test-secret' });
    await client.createSession();

    expect(capturedBody.client_secret).toBe('test-secret');
    expect(capturedBody).not.toHaveProperty('client_assertion');
  });

  test('sends no auth fields for a public client', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const client = makeClient();
    await client.createSession();

    expect(capturedBody).not.toHaveProperty('client_secret');
    expect(capturedBody).not.toHaveProperty('client_assertion');
  });

  test('sends client_assertion for private_key_jwt with a PEM key', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const { privateKey } = await generateRsaKeyPair();
    const pem = await exportPrivateKeyToPem(privateKey);
    const client = makeClient({ clientAssertionSigningKey: pem, clientAssertionSigningAlg: 'RS256' });
    await client.createSession();

    expect(capturedBody.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    const jwt = capturedBody.client_assertion as string;
    expect(typeof jwt).toBe('string');
    expect(decodeProtectedHeader(jwt).alg).toBe('RS256');
    const claims = decodeJwt(jwt);
    expect(claims.iss).toBe(clientId);
    expect(claims.sub).toBe(clientId);
    expect(claims.aud).toBe(`https://${domain}/`);
    expect(typeof claims.jti).toBe('string');
    const ttl = (claims.exp as number) - (claims.iat as number);
    expect(ttl).toBe(120);
    expect(capturedBody).not.toHaveProperty('client_secret');
  });

  test('sends client_assertion for private_key_jwt with a CryptoKey', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
          session_expires_in: sessionExpiresIn,
        });
      })
    );

    const { privateKey } = await generateRsaKeyPair();
    const client = makeClient({ clientAssertionSigningKey: privateKey });
    await client.createSession();

    const jwt = capturedBody.client_assertion as string;
    expect(typeof jwt).toBe('string');
    expect(decodeJwt(jwt).aud).toBe(`https://${domain}/`);
    expect(capturedBody).not.toHaveProperty('client_secret');
  });
});

// ─── sessionTokenExpiresAt ────────────────────────────────────────────────────

describe('sessionTokenExpiresAt', () => {
  test('set on createSession from session_expires_in', async () => {
    const client = makeClient();
    const before = Math.floor(Date.now() / 1000);
    const session = await client.createSession();
    const after = Math.floor(Date.now() / 1000);

    expect(session.sessionTokenExpiresAt).toBeGreaterThanOrEqual(before + sessionExpiresIn);
    expect(session.sessionTokenExpiresAt).toBeLessThanOrEqual(after + sessionExpiresIn);
  });

  test('set on getTokenSilently re-mint and counts down from original expiry', async () => {
    const client = makeClient();
    const before = Math.floor(Date.now() / 1000);
    const session = await client.getTokenSilently({ sessionToken });
    const after = Math.floor(Date.now() / 1000);

    // default handler returns sessionExpiresIn - 3600 for re-mint
    const expected = sessionExpiresIn - 3600;
    expect(session.sessionTokenExpiresAt).toBeGreaterThanOrEqual(before + expected);
    expect(session.sessionTokenExpiresAt).toBeLessThanOrEqual(after + expected);
  });

  test('renewal sessionTokenExpiresAt is less than create sessionTokenExpiresAt', async () => {
    const client = makeClient();
    const created = await client.createSession();
    const renewed = await client.getTokenSilently({ sessionToken });

    expect(renewed.sessionTokenExpiresAt!).toBeLessThan(created.sessionTokenExpiresAt!);
  });

  test('sessionTokenExpiresAt is undefined when session_expires_in is absent', async () => {
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
        })
      )
    );

    const client = makeClient();
    const session = await client.createSession();

    expect(session.sessionTokenExpiresAt).toBeUndefined();
  });
});
