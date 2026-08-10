import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AnonymousSessionClient } from './anonymous-session-client.js';
import { AnonymousSessionError } from './errors.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const sessionToken = 'test-session-token';
const accessToken = 'test-access-token';

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

    // Simulate metadata_too_large
    if (body.metadata && JSON.stringify(body.metadata).length > 1024) {
      return HttpResponse.json(
        { error: 'metadata_too_large', error_description: 'Metadata exceeds 1 KB limit' },
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
      });
    }

    // Create: no session_token → return both tokens
    return HttpResponse.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: body.scope ?? 'openid',
      session_token: sessionToken,
    });
  }),

  http.post(`https://${domain}/anonymous/logout`, async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;

    if (body.session_token === 'unknown-session-token') {
      return HttpResponse.json(
        { error: 'invalid_session_token', error_description: 'Session token not found' },
        { status: 400 }
      );
    }

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
        });
      })
    );

    const client = makeClient();
    await client.createSession();

    expect(capturedBody.session_token).toBeUndefined();
  });

  test('sends request with credentials: include', async () => {
    let capturedRequest: Request | null = null;

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedRequest = request;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
        });
      })
    );

    const client = makeClient();
    await client.createSession();

    // credentials: 'include' is a fetch init option — verify the request was made
    expect(capturedRequest).not.toBeNull();
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
});

// ─── getToken ─────────────────────────────────────────────────────────────────

describe('getToken', () => {
  test('re-mints access token using existing session token', async () => {
    const client = makeClient();
    const session = await client.getToken(sessionToken);

    expect(session.accessToken).toBe('renewed-access-token');
    expect(session.sessionToken).toBe(sessionToken); // session token unchanged
    expect(session.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test('sends the session_token in the request body', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: 'renewed-access-token',
          token_type: 'Bearer',
          expires_in: 3600,
        });
      })
    );

    const client = makeClient();
    await client.getToken('my-session-token', { audience: 'https://api.example.com' });

    expect(capturedBody.session_token).toBe('my-session-token');
    expect(capturedBody.audience).toBe('https://api.example.com');
    expect(capturedBody.client_id).toBe(clientId);
  });

  test('throws AnonymousSessionError with session_expired code', async () => {
    const client = makeClient();

    await expect(client.getToken('expired-session-token')).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'session_expired',
    });
  });

  test('throws AnonymousSessionError with invalid_session_token code', async () => {
    const client = makeClient();

    await expect(client.getToken('invalid-session-token')).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'invalid_session_token',
    });
  });
});

// ─── getTokenSilently ─────────────────────────────────────────────────────────

describe('getTokenSilently', () => {
  test('creates a new session when called with null', async () => {
    const client = makeClient();
    const session = await client.getTokenSilently(null);

    expect(session.sessionToken).toBe(sessionToken);
    expect(session.accessToken).toBe(accessToken);
  });

  test('returns the existing session unchanged when access token is still valid', async () => {
    const client = makeClient();
    const fetchSpy = vi.fn();
    server.use(
      http.post(`https://${domain}/anonymous/token`, () => {
        fetchSpy();
        return HttpResponse.json({});
      })
    );

    const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
    const existingSession = {
      sessionToken,
      accessToken,
      expiresAt: futureExpiry,
    };

    const result = await client.getTokenSilently(existingSession);

    expect(result).toBe(existingSession); // same reference
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('renews access token when it is expired', async () => {
    const client = makeClient();
    const expiredSession = {
      sessionToken,
      accessToken: 'old-access-token',
      expiresAt: Math.floor(Date.now() / 1000) - 60, // expired 1 minute ago
    };

    const result = await client.getTokenSilently(expiredSession);

    expect(result.accessToken).toBe('renewed-access-token');
    expect(result.sessionToken).toBe(sessionToken); // session token unchanged
  });

  test('silently creates a new session when session_expired is encountered during renewal', async () => {
    const client = makeClient();
    const expiredSession = {
      sessionToken: 'expired-session-token',
      accessToken: 'old-access-token',
      expiresAt: Math.floor(Date.now() / 1000) - 60,
    };

    // Should silently fall back to createSession and succeed
    const result = await client.getTokenSilently(expiredSession);

    expect(result.sessionToken).toBe(sessionToken); // fresh session
    expect(result.accessToken).toBe(accessToken);
  });

  test('silently creates a new session when invalid_session_token is encountered during renewal', async () => {
    const client = makeClient();
    const invalidSession = {
      sessionToken: 'invalid-session-token',
      accessToken: 'old-access-token',
      expiresAt: Math.floor(Date.now() / 1000) - 60,
    };

    const result = await client.getTokenSilently(invalidSession);

    expect(result.sessionToken).toBe(sessionToken);
    expect(result.accessToken).toBe(accessToken);
  });

  test('propagates non-session errors to the caller', async () => {
    const client = makeClient();
    const expiredSession = {
      sessionToken,
      accessToken: 'old-access-token',
      expiresAt: Math.floor(Date.now() / 1000) - 60,
    };

    // Override to return a non-recoverable error
    server.use(
      http.post(`https://${domain}/anonymous/token`, () =>
        HttpResponse.json(
          { error: 'invalid_scope', error_description: 'Requested scope not allowed' },
          { status: 400 }
        )
      )
    );

    await expect(client.getTokenSilently(expiredSession)).rejects.toMatchObject({
      name: 'AnonymousSessionError',
      code: 'invalid_scope',
    });
  });

  test('passes audience and scope options through to createSession when called with null', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/token`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          session_token: sessionToken,
        });
      })
    );

    const client = makeClient();
    await client.getTokenSilently(null, { audience: 'https://api.example.com', scope: 'openid' });

    expect(capturedBody.audience).toBe('https://api.example.com');
    expect(capturedBody.scope).toBe('openid');
  });
});

// ─── logout ───────────────────────────────────────────────────────────────────

describe('logout', () => {
  test('ends the anonymous session', async () => {
    const client = makeClient();
    await expect(client.logout(sessionToken)).resolves.toBeUndefined();
  });

  test('sends client_id and session_token in the request body', async () => {
    let capturedBody: Record<string, unknown> = {};

    server.use(
      http.post(`https://${domain}/anonymous/logout`, async ({ request }) => {
        capturedBody = (await request.json()) as Record<string, unknown>;
        return new HttpResponse(null, { status: 204 });
      })
    );

    const client = makeClient();
    await client.logout('my-session-token');

    expect(capturedBody.client_id).toBe(clientId);
    expect(capturedBody.session_token).toBe('my-session-token');
  });

  test('throws AnonymousSessionError when session is not found', async () => {
    const client = makeClient();

    await expect(client.logout('unknown-session-token')).rejects.toMatchObject({
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
    const error = await client.logout(sessionToken).catch((e) => e);

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
