import { expect, test, afterAll, afterEach, beforeAll, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ServerClient } from '../server-client.js';
import { SignUpError, ChangePasswordError } from '../index.js';
import { DefaultStateStore } from '../test-utils/default-state-store.js';

const domain = 'auth0.local';
const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const makeClient = (domainOption: string | (() => Promise<string>) = domain) =>
  new ServerClient({
    domain: domainOption,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore: new DefaultStateStore({ secret: '<secret>' }),
  });

test('exposes a database sub-client with signUp and changePassword', () => {
  const sc = makeClient();
  expect(sc.database).toBeDefined();
  expect(typeof sc.database.signUp).toBe('function');
  expect(typeof sc.database.changePassword).toBe('function');
});

test('database.signUp delegates and writes no session', async () => {
  let captured: Record<string, unknown> = {};
  server.use(http.post(`https://${domain}/dbconnections/signup`, async ({ request }) => {
    captured = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({ _id: 'abc', email: 'a@b.com', email_verified: false });
  }));
  const stateStore = new DefaultStateStore({ secret: '<secret>' });
  const setSpy = vi.spyOn(stateStore, 'set');
  const sc = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore,
  });

  const res = await sc.database.signUp({ email: 'a@b.com', password: 'pw', connection: 'db' });

  expect(res.id).toBe('abc');
  expect(captured.client_id).toBe('<client_id>');
  expect(setSpy).not.toHaveBeenCalled();
});

test('database.changePassword delegates and writes no session', async () => {
  server.use(http.post(`https://${domain}/dbconnections/change_password`, () =>
    new HttpResponse("We've just sent you an email to reset your password.", { status: 200 })));
  const stateStore = new DefaultStateStore({ secret: '<secret>' });
  const setSpy = vi.spyOn(stateStore, 'set');
  const sc = new ServerClient({
    domain,
    clientId: '<client_id>',
    clientSecret: '<client_secret>',
    transactionStore: { get: vi.fn(), set: vi.fn(), delete: vi.fn() },
    stateStore,
  });

  const msg = await sc.database.changePassword({ email: 'a@b.com', connection: 'db' });

  expect(msg).toContain('reset your password');
  expect(setSpy).not.toHaveBeenCalled();
});

test('database.signUp resolves the domain in resolver mode', async () => {
  let host: string | undefined;
  server.use(http.post(`https://${domain}/dbconnections/signup`, ({ request }) => {
    host = new URL(request.url).host;
    return HttpResponse.json({ id: 'x', email: 'a@b.com', email_verified: true });
  }));

  const res = await makeClient(async () => domain).database.signUp({
    email: 'a@b.com',
    password: 'pw',
    connection: 'db',
  });

  expect(res.id).toBe('x');
  expect(host).toBe(domain);
});

test('database.signUp surfaces SignUpError from the underlying client', async () => {
  server.use(http.post(`https://${domain}/dbconnections/signup`, () =>
    HttpResponse.json({ error: 'invalid_signup', error_description: 'Invalid sign up' }, { status: 400 })));

  await expect(
    makeClient().database.signUp({ email: 'a@b.com', password: 'pw', connection: 'db' })
  ).rejects.toBeInstanceOf(SignUpError);
});

test('database.changePassword surfaces ChangePasswordError from the underlying client', async () => {
  server.use(http.post(`https://${domain}/dbconnections/change_password`, () =>
    HttpResponse.json({ error: 'bad', error_description: 'nope' }, { status: 400 })));

  await expect(
    makeClient().database.changePassword({ email: 'a@b.com', connection: 'db' })
  ).rejects.toBeInstanceOf(ChangePasswordError);
});
