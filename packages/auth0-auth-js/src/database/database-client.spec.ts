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

  test('missing email throws ChangePasswordError before request', async () => {
    await expect(makeClient().changePassword({ connection: 'db' } as unknown as ChangePasswordOptions))
      .rejects.toBeInstanceOf(ChangePasswordError);
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
