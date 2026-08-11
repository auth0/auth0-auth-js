import { expect, test, describe, afterAll, afterEach, beforeAll, vi } from 'vitest';
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

describe('per-request options (RequestOptions)', () => {
  // Both assertions below read the header off the request MSW actually received, so they
  // only pass when requestOptions travels all the way from `ServerClient.database` into
  // the outbound fetch. Asserting the returned value alone would not catch a dropped
  // requestOptions.
  const captureSignupHeader = () => {
    const seen: (string | null)[] = [];
    server.use(http.post(`https://${domain}/dbconnections/signup`, ({ request }) => {
      seen.push(request.headers.get('x-request-tag'));
      return HttpResponse.json({ _id: 'abc', email: 'a@b.com', email_verified: false });
    }));
    return seen;
  };

  const captureChangePasswordHeader = () => {
    const seen: (string | null)[] = [];
    server.use(http.post(`https://${domain}/dbconnections/change_password`, ({ request }) => {
      seen.push(request.headers.get('x-request-tag'));
      return new HttpResponse("We've just sent you an email to reset your password.", { status: 200 });
    }));
    return seen;
  };

  test('database.signUp forwards per-request headers to the outbound request', async () => {
    const seen = captureSignupHeader();

    const res = await makeClient().database.signUp(
      { email: 'a@b.com', password: 'pw', connection: 'db' },
      undefined,
      { headers: { 'X-Request-Tag': 'signup-1' } }
    );

    expect(res.id).toBe('abc');
    expect(seen).toEqual(['signup-1']);
  });

  test('database.signUp sends no per-request header when requestOptions is omitted', async () => {
    const seen = captureSignupHeader();

    // The forwarded call first, the bare call second: the pair proves the header is
    // carried when supplied and that omitting requestOptions stays backward compatible.
    await makeClient().database.signUp(
      { email: 'a@b.com', password: 'pw', connection: 'db' },
      undefined,
      { headers: { 'X-Request-Tag': 'signup-2' } }
    );
    const res = await makeClient().database.signUp({ email: 'a@b.com', password: 'pw', connection: 'db' });

    expect(res.id).toBe('abc');
    expect(seen).toEqual(['signup-2', null]);
  });

  test('database.signUp forwards a per-request customFetch', async () => {
    captureSignupHeader();
    const perRequestFetch = vi.fn().mockImplementation(fetch);

    await makeClient().database.signUp(
      { email: 'a@b.com', password: 'pw', connection: 'db' },
      undefined,
      { customFetch: perRequestFetch }
    );

    expect(perRequestFetch).toHaveBeenCalledOnce();
  });

  test('database.signUp forwards an already-aborted per-request signal', async () => {
    const seen = captureSignupHeader();
    const controller = new AbortController();
    controller.abort();

    // The abort surfaces as the sub-client's network-failure error, and the request
    // never reaches the endpoint.
    await expect(
      makeClient().database.signUp({ email: 'a@b.com', password: 'pw', connection: 'db' }, undefined, {
        signal: controller.signal,
      })
    ).rejects.toBeInstanceOf(SignUpError);
    expect(seen).toEqual([]);
  });

  test('database.changePassword forwards per-request headers to the outbound request', async () => {
    const seen = captureChangePasswordHeader();

    const msg = await makeClient().database.changePassword({ email: 'a@b.com', connection: 'db' }, undefined, {
      headers: { 'X-Request-Tag': 'change-1' },
    });

    expect(msg).toContain('reset your password');
    expect(seen).toEqual(['change-1']);
  });

  test('database.changePassword sends no per-request header when requestOptions is omitted', async () => {
    const seen = captureChangePasswordHeader();

    await makeClient().database.changePassword({ email: 'a@b.com', connection: 'db' }, undefined, {
      headers: { 'X-Request-Tag': 'change-2' },
    });
    const msg = await makeClient().database.changePassword({ email: 'a@b.com', connection: 'db' });

    expect(msg).toContain('reset your password');
    expect(seen).toEqual(['change-2', null]);
  });

  test('database.changePassword forwards a per-request customFetch', async () => {
    captureChangePasswordHeader();
    const perRequestFetch = vi.fn().mockImplementation(fetch);

    await makeClient().database.changePassword({ email: 'a@b.com', connection: 'db' }, undefined, {
      customFetch: perRequestFetch,
    });

    expect(perRequestFetch).toHaveBeenCalledOnce();
  });

  test('database.signUp forwards requestOptions in resolver mode', async () => {
    const seen = captureSignupHeader();

    await makeClient(async () => domain).database.signUp(
      { email: 'a@b.com', password: 'pw', connection: 'db' },
      undefined,
      { headers: { 'X-Request-Tag': 'resolver-1' } }
    );

    expect(seen).toEqual(['resolver-1']);
  });
});
