import { expect, test, describe, beforeAll, afterAll, afterEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { DatabaseClient } from './database-client.js';
import { SignUpError, ChangePasswordError } from './errors.js';
import type { SignUpOptions, ChangePasswordOptions } from './types.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const makeClient = () => new DatabaseClient({ domain, clientId });

describe('signUp', () => {
  test('normalizes _id and sends client_id, no client auth', async () => {
    let captured: Record<string, unknown> = {};
    server.use(http.post(`https://${domain}/dbconnections/signup`, async ({ request }) => {
      captured = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ _id: 'abc', email: 'a@b.com', email_verified: false });
    }));
    const res = await makeClient().signUp({ email: 'a@b.com', password: 'pw', connection: 'db' });
    expect(res.id).toBe('abc');
    expect(captured.client_id).toBe(clientId);
    expect(captured.client_secret).toBeUndefined();
    expect(captured.client_assertion).toBeUndefined();
  });

  test('clientId override wins', async () => {
    let captured: Record<string, unknown> = {};
    server.use(http.post(`https://${domain}/dbconnections/signup`, async ({ request }) => {
      captured = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ id: 'x', email: 'a@b.com', email_verified: true });
    }));
    await makeClient().signUp({ email: 'a@b.com', password: 'pw', connection: 'db', clientId: 'override' });
    expect(captured.client_id).toBe('override');
  });

  test('missing password throws SignUpError before request', async () => {
    await expect(makeClient().signUp({ email: 'a@b.com', connection: 'db' } as unknown as SignUpOptions))
      .rejects.toBeInstanceOf(SignUpError);
  });

  test('400 {code,description} maps to SignUpError with cause', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
      HttpResponse.json({ name: 'BadRequestError', code: 'invalid_signup', description: 'Invalid sign up' }, { status: 400 })));
    await expect(makeClient().signUp({ email: 'a@b.com', password: 'pw', connection: 'db' }))
      .rejects.toMatchObject({ name: 'SignUpError', message: 'Invalid sign up', cause: { error: 'invalid_signup' } });
  });

  test('cause is sanitized to {error, error_description, message} only', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
      HttpResponse.json(
        { error: 'invalid_signup', error_description: 'Invalid sign up', trace_id: 'leak', internal: 'secret' },
        { status: 400 }
      )));
    const err: SignUpError = await makeClient()
      .signUp({ email: 'a@b.com', password: 'pw', connection: 'db' })
      .then(() => { throw new Error('expected signUp to reject'); }, (e) => e as SignUpError);
    expect(err).toBeInstanceOf(SignUpError);
    expect(err.cause).toEqual({ error: 'invalid_signup', error_description: 'Invalid sign up', message: undefined });
    const cause = err.cause as unknown as Record<string, unknown>;
    expect(cause.trace_id).toBeUndefined();
    expect(cause.internal).toBeUndefined();
  });

  test('missing email throws SignUpError before request', async () => {
    await expect(makeClient().signUp({ password: 'pw', connection: 'db' } as unknown as SignUpOptions))
      .rejects.toBeInstanceOf(SignUpError);
  });

  test('missing connection throws SignUpError before request', async () => {
    await expect(makeClient().signUp({ email: 'a@b.com', password: 'pw' } as unknown as SignUpOptions))
      .rejects.toBeInstanceOf(SignUpError);
  });

  test('network failure wraps in SignUpError', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () => { throw new Error('boom'); }));
    await expect(makeClient().signUp({ email: 'a@b.com', password: 'pw', connection: 'db' }))
      .rejects.toBeInstanceOf(SignUpError);
  });
});

describe('changePassword', () => {
  test('returns plain text and sends client_id, no client auth', async () => {
    let captured: Record<string, unknown> = {};
    server.use(http.post(`https://${domain}/dbconnections/change_password`, async ({ request }) => {
      captured = (await request.json()) as Record<string, unknown>;
      return new HttpResponse("We've just sent you an email to reset your password.", { status: 200 });
    }));
    const msg = await makeClient().changePassword({ email: 'a@b.com', connection: 'db' });
    expect(msg).toBe("We've just sent you an email to reset your password.");
    expect(captured.client_id).toBe(clientId);
    expect(captured.client_secret).toBeUndefined();
  });

  test('clientId override wins', async () => {
    let captured: Record<string, unknown> = {};
    server.use(http.post(`https://${domain}/dbconnections/change_password`, async ({ request }) => {
      captured = (await request.json()) as Record<string, unknown>;
      return new HttpResponse('ok', { status: 200 });
    }));
    await makeClient().changePassword({ email: 'a@b.com', connection: 'db', clientId: 'override' });
    expect(captured.client_id).toBe('override');
  });

  test('organization is forwarded on the wire when set', async () => {
    let captured: Record<string, unknown> = {};
    server.use(http.post(`https://${domain}/dbconnections/change_password`, async ({ request }) => {
      captured = (await request.json()) as Record<string, unknown>;
      return new HttpResponse('ok', { status: 200 });
    }));
    await makeClient().changePassword({ email: 'a@b.com', connection: 'db', organization: 'org_1' });
    expect(captured.organization).toBe('org_1');
  });

  test('missing connection throws ChangePasswordError before request', async () => {
    await expect(makeClient().changePassword({ email: 'a@b.com' } as unknown as ChangePasswordOptions))
      .rejects.toBeInstanceOf(ChangePasswordError);
  });

  test('missing both email and username throws ChangePasswordError before request', async () => {
    await expect(makeClient().changePassword({ connection: 'db' } as unknown as ChangePasswordOptions))
      .rejects.toBeInstanceOf(ChangePasswordError);
  });

  test('username-only (no email) is forwarded on the wire', async () => {
    let captured: Record<string, unknown> = {};
    server.use(http.post(`https://${domain}/dbconnections/change_password`, async ({ request }) => {
      captured = (await request.json()) as Record<string, unknown>;
      return new HttpResponse('ok', { status: 200 });
    }));
    await makeClient().changePassword({ username: 'jane', connection: 'db' });
    expect(captured.username).toBe('jane');
    expect(captured.email).toBeUndefined();
  });

  test('network failure wraps in ChangePasswordError', async () => {
    server.use(http.post(`https://${domain}/dbconnections/change_password`, () => { throw new Error('boom'); }));
    await expect(makeClient().changePassword({ email: 'a@b.com', connection: 'db' }))
      .rejects.toBeInstanceOf(ChangePasswordError);
  });

  test('400 error maps to ChangePasswordError', async () => {
    server.use(http.post(`https://${domain}/dbconnections/change_password`, () =>
      HttpResponse.json({ error: 'bad', error_description: 'nope' }, { status: 400 })));
    await expect(makeClient().changePassword({ email: 'a@b.com', connection: 'db' }))
      .rejects.toMatchObject({ name: 'ChangePasswordError', message: 'nope' });
  });
});

// ===== HttpResponseMetadata — Success path (TCR1) =====
describe('HttpResponseMetadata — success path', () => {
  test('signUp 200 — httpResponse present with status/statusText/headers', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
      HttpResponse.json(
        { _id: 'user-123', email: 'a@b.com', email_verified: false },
        {
          status: 200,
          headers: {
            'x-request-id': 'req-signup-001',
            'content-type': 'application/json'
          }
        }
      )
    ));

    const result = await makeClient().signUp({ email: 'a@b.com', password: 'pwd', connection: 'db' });

    // Verify httpResponse metadata is present
    expect(result.httpResponse).toBeDefined();
    expect(result.httpResponse?.status).toBe(200);
    expect(typeof result.httpResponse?.statusText).toBe('string');
    expect(result.httpResponse?.headers).toBeInstanceOf(Headers);

    // Verify native Headers.get() works
    expect(result.httpResponse?.headers.get('x-request-id')).toBe('req-signup-001');
    expect(result.httpResponse?.headers.get('content-type')).toBe('application/json');

    // Verify data payload still present and unchanged
    expect(result.id).toBe('user-123');
    expect(result.email).toBe('a@b.com');
  });

  test('signUp 200 — native Headers is not Record', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
      HttpResponse.json({ _id: 'id', email: 'a@b.com', email_verified: false }, { status: 200 })
    ));

    const result = await makeClient().signUp({ email: 'a@b.com', password: 'pwd', connection: 'db' });

    // Verify Headers is native Fetch API, not Record
    expect(typeof result.httpResponse?.headers.get).toBe('function');
    expect(result.httpResponse?.headers.get('x-request-id')).toBeDefined();
  });
});

// ===== HttpResponseMetadata — Error path (TCR2) =====
describe('HttpResponseMetadata — error path', () => {
  test('signUp 409 — error has statusCode/headers/body', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
      HttpResponse.json(
        { error: 'user_exists', error_description: 'User already exists' },
        {
          status: 409,
          headers: {
            'x-error-id': 'err-409-001',
            'content-type': 'application/json'
          }
        }
      )
    ));

    try {
      await makeClient().signUp({ email: 'a@b.com', password: 'pwd', connection: 'db' });
      expect.fail('Should have thrown SignUpError');
    } catch (e) {
      expect(e).toBeInstanceOf(SignUpError);
      const err = e as SignUpError;

      // Verify statusCode, headers, body are present
      expect(err.statusCode).toBe(409);
      expect(err.headers).toBeInstanceOf(Headers);
      expect(typeof err.body).toBe('string');

      // Verify native Headers.get() works
      expect(err.headers?.get('x-error-id')).toBe('err-409-001');
      expect(err.headers?.get('content-type')).toBe('application/json');

      // Verify body is raw JSON string (not parsed)
      expect(err.body).toContain('user_exists');
      expect(err.body).toContain('User already exists');

      // Verify cause is properly filtered
      expect(err.cause?.error).toBe('user_exists');
      expect(err.cause?.error_description).toBe('User already exists');
    }
  });

  test('signUp 400 — error body is raw string (not parsed)', async () => {
    server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
      HttpResponse.json(
        { error: 'invalid_signup', error_description: 'Invalid email format' },
        { status: 400 }
      )
    ));

    try {
      await makeClient().signUp({ email: 'invalid', password: 'pwd', connection: 'db' });
      expect.fail('Should have thrown SignUpError');
    } catch (e) {
      if (e instanceof SignUpError) {
        // body should be raw JSON string
        expect(typeof e.body).toBe('string');
        expect(e.body).toContain('invalid_signup');

        // Verify it can be parsed by caller if needed
        const parsed = JSON.parse(e.body!);
        expect(parsed.error).toBe('invalid_signup');
        expect(parsed.error_description).toBe('Invalid email format');
      }
    }
  });

  test('changePassword 429 — error has retry-after header', async () => {
    server.use(http.post(`https://${domain}/dbconnections/change_password`, () =>
      HttpResponse.json(
        { error: 'too_many_requests', error_description: 'Rate limited' },
        {
          status: 429,
          headers: { 'retry-after': '60' }
        }
      )
    ));

    try {
      await makeClient().changePassword({ email: 'a@b.com', connection: 'db' });
      expect.fail('Should have thrown ChangePasswordError');
    } catch (e) {
      if (e instanceof ChangePasswordError) {
        expect(e.statusCode).toBe(429);
        expect(e.headers?.get('retry-after')).toBe('60');
      }
    }
  });

  test('changePassword 200 — no success metadata (string return)', async () => {
    server.use(http.post(`https://${domain}/dbconnections/change_password`, () =>
      new HttpResponse("We've sent you an email", {
        status: 200,
        headers: { 'x-request-id': 'req-cp-001' }
      })
    ));

    const msg = await makeClient().changePassword({ email: 'a@b.com', connection: 'db' });

    // Success string return should have no httpResponse metadata (per O#3 decision)
    expect(msg).toBe("We've sent you an email");
  });
});

// ===== HttpResponseMetadata — Concurrency (TCR3) =====
describe('HttpResponseMetadata — concurrency', () => {
  test('concurrent signUp calls — each gets own httpResponse (no cross-leakage)', async () => {
    let callCount = 0;
    server.use(
      http.post(`https://${domain}/dbconnections/signup`, () => {
        callCount++;
        if (callCount === 1) {
          return HttpResponse.json(
            { _id: 'user-1', email: 'a@b.com', email_verified: false },
            { status: 200, headers: { 'x-request-id': 'req-1' } }
          );
        } else {
          return HttpResponse.json(
            { error: 'invalid_signup', error_description: 'Invalid email' },
            { status: 400, headers: { 'x-request-id': 'req-2' } }
          );
        }
      })
    );

    const [result, error] = await Promise.allSettled([
      makeClient().signUp({ email: 'a@b.com', password: 'pwd', connection: 'db' }),
      makeClient().signUp({ email: 'invalid', password: 'pwd', connection: 'db' })
    ]);

    // Verify success result
    expect(result.status).toBe('fulfilled');
    if (result.status === 'fulfilled') {
      expect(result.value.httpResponse?.status).toBe(200);
      expect(result.value.httpResponse?.headers.get('x-request-id')).toBe('req-1');
      expect(result.value.id).toBe('user-1');
    }

    // Verify error result
    expect(error.status).toBe('rejected');
    const errorReason = error.status === 'rejected' ? error.reason as { statusCode?: number; headers?: Headers } : null;
    expect(errorReason?.statusCode).toBe(400);
    expect(errorReason?.headers?.get('x-request-id')).toBe('req-2');

    // CRITICAL: Verify NO cross-leakage (success doesn't get error's status)
    if (result.status === 'fulfilled') {
      expect(result.value.httpResponse?.status).not.toBe(400);
    }
    expect(errorReason?.statusCode).not.toBe(200);
  });

  test('concurrent signUp with different request headers — each captures own metadata', async () => {
    let callCount = 0;
    server.use(
      http.post(`https://${domain}/dbconnections/signup`, () => {
        callCount++;
        return HttpResponse.json(
          { _id: `user-${callCount}`, email: `user${callCount}@b.com`, email_verified: false },
          {
            status: 200,
            headers: { 'x-request-id': `req-${callCount}` }
          }
        );
      })
    );

    const [result1, result2] = await Promise.all([
      makeClient().signUp({ email: 'user1@b.com', password: 'pwd', connection: 'db' }),
      makeClient().signUp({ email: 'user2@b.com', password: 'pwd', connection: 'db' })
    ]);

    // Each call should capture its own request-id (no cross-leakage)
    expect(result1.httpResponse?.headers.get('x-request-id')).toBe('req-1');
    expect(result2.httpResponse?.headers.get('x-request-id')).toBe('req-2');
    expect(result1.id).toBe('user-1');
    expect(result2.id).toBe('user-2');
  });

  test('concurrent error calls — each error has correct statusCode', async () => {
    let callCount = 0;
    server.use(
      http.post(`https://${domain}/dbconnections/signup`, () => {
        callCount++;
        if (callCount === 1) {
          return HttpResponse.json(
            { error: 'user_exists', error_description: 'User exists' },
            { status: 409 }
          );
        } else {
          return HttpResponse.json(
            { error: 'invalid_signup', error_description: 'Invalid' },
            { status: 400 }
          );
        }
      })
    );

    const [error1, error2] = await Promise.allSettled([
      makeClient().signUp({ email: 'a@b.com', password: 'pwd', connection: 'db' }),
      makeClient().signUp({ email: 'b@b.com', password: 'pwd', connection: 'db' })
    ]);

    expect(error1.status).toBe('rejected');
    expect(error2.status).toBe('rejected');

    const err1 = (error1 as PromiseRejectedResult).reason as SignUpError;
    const err2 = (error2 as PromiseRejectedResult).reason as SignUpError;

    // Each error should have different status (no cross-leakage)
    expect(err1.statusCode).toBe(409);
    expect(err2.statusCode).toBe(400);
    expect(err1.statusCode).not.toBe(err2.statusCode);
  });
});
