import { afterEach, expect, test, vi } from 'vitest';
import { ApiClient } from './api-client.js';
import { AuthServerUnavailableError, VerifyAccessTokenError } from './errors.js';
import { generateToken, jwks } from './test-utils/tokens.js';

const domain = 'auth0.local';
const audience = '<audience>';
const discoveryUrl = `https://${domain}/.well-known/openid-configuration`;
const jwksUrl = `https://${domain}/.well-known/jwks.json`;
const metadata = { issuer: `https://${domain}/`, jwks_uri: jwksUrl };

type Handler = () => Response | Promise<Response>;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const timeoutError = () => Object.assign(new Error('The operation timed out'), { name: 'TimeoutError' });

function makeClient(handlers: { discovery?: Handler; jwks?: Handler }, extra: object = {}) {
  const state = { discovery: handlers.discovery ?? (() => json(metadata)), jwks: handlers.jwks ?? (() => json({ keys: jwks })) };
  const customFetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url === discoveryUrl) return state.discovery();
    if (url === jwksUrl) return state.jwks();
    return new Response('not found', { status: 404 });
  });
  const client = new ApiClient({ domain, audience, customFetch: customFetch as typeof fetch, ...extra });
  return { client, customFetch, state };
}

async function outcome(client: ApiClient, accessToken: string) {
  return client.verifyAccessToken({ accessToken }).then(
    () => undefined,
    (e: unknown) => e as Error & { statusCode?: number; code?: string; headers?: unknown }
  );
}

function expectUnavailable(err: (Error & { statusCode?: number; code?: string; headers?: unknown }) | undefined) {
  expect(err).toBeInstanceOf(AuthServerUnavailableError);
  expect(err).toBeInstanceOf(VerifyAccessTokenError);
  expect(err?.statusCode).toBe(503);
  expect(err?.code).toBe('auth_server_unavailable');
  expect(err?.name).toBe('AuthServerUnavailableError');
  expect(err?.headers).toBeUndefined();
}

function expectRejected(err: (Error & { statusCode?: number; code?: string }) | undefined) {
  expect(err).toBeInstanceOf(VerifyAccessTokenError);
  expect(err).not.toBeInstanceOf(AuthServerUnavailableError);
  expect(err?.statusCode).toBe(401);
}

afterEach(() => {
  vi.useRealTimers();
});

const outageRows: [string, Handler][] = [
  ['network error', () => { throw new TypeError('fetch failed'); }],
  ['timeout', () => { throw timeoutError(); }],
  ['HTTP 500', () => new Response('boom', { status: 500 })],
  ['HTTP 503', () => new Response('down', { status: 503 })],
  ['HTTP 429', () => new Response('slow down', { status: 429 })],
];

for (const [name, handler] of outageRows) {
  test(`verifyAccessToken - discovery ${name} raises AuthServerUnavailableError`, async () => {
    const { client } = makeClient({ discovery: handler });
    const err = await outcome(client, await generateToken(domain, '<sub>', audience));
    expectUnavailable(err);
  });

  test(`verifyAccessToken - JWKS ${name} raises AuthServerUnavailableError`, async () => {
    const { client } = makeClient({ jwks: handler });
    const err = await outcome(client, await generateToken(domain, '<sub>', audience));
    expectUnavailable(err);
    expect(err?.message).toContain('JWKS request failed');
  });
}

test('verifyAccessToken - discovery outage is not cached and the next request recovers', async () => {
  const { client, state } = makeClient({ discovery: () => new Response('down', { status: 503 }) });
  const accessToken = await generateToken(domain, '<sub>', audience);
  expectUnavailable(await outcome(client, accessToken));

  state.discovery = () => json(metadata);
  expect(await outcome(client, accessToken)).toBeUndefined();
});

test('verifyAccessToken - JWKS outage is not cached and the next request recovers', async () => {
  const { client, state } = makeClient({ jwks: () => new Response('down', { status: 503 }) });
  const accessToken = await generateToken(domain, '<sub>', audience);
  expectUnavailable(await outcome(client, accessToken));

  state.jwks = () => json({ keys: jwks });
  expect(await outcome(client, accessToken)).toBeUndefined();
});

test('verifyAccessToken - the multiple-domains path reports a discovery outage', async () => {
  const customFetch = vi.fn(async () => new Response('down', { status: 503 }));
  const client = new ApiClient({ domains: [domain], audience, customFetch: customFetch as typeof fetch });
  expectUnavailable(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - discovery 404 stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({ discovery: () => new Response('nope', { status: 404 }) });
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - malformed discovery body stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({
    discovery: () => new Response('not json', { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - discovery without jwks_uri stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({ discovery: () => json({ issuer: metadata.issuer }) });
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - JWKS 404 stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({ jwks: () => new Response('nope', { status: 404 }) });
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - malformed JWKS body stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({
    jwks: () => new Response('not json', { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - an empty key set stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({ jwks: () => json({ keys: [] }) });
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience)));
});

test('verifyAccessToken - a bad signature stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({});
  const token = await generateToken(domain, '<sub>', audience);
  const [header, payload, signature = ''] = token.split('.');
  const flipped = (signature.startsWith('A') ? 'B' : 'A') + signature.slice(1);
  expectRejected(await outcome(client, `${header}.${payload}.${flipped}`));
});

test('verifyAccessToken - an expired token stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({});
  const past = Math.floor(Date.now() / 1000) - 3600;
  expectRejected(await outcome(client, await generateToken(domain, '<sub>', audience, undefined, past - 60, past)));
});

function withKid(token: string, kid: string) {
  const [header = '', payload, signature] = token.split('.');
  const decoded = JSON.parse(Buffer.from(header, 'base64url').toString());
  const next = Buffer.from(JSON.stringify({ ...decoded, kid })).toString('base64url');
  return `${next}.${payload}.${signature}`;
}

test('verifyAccessToken - an unknown kid after a successful JWKS fetch stays a VerifyAccessTokenError', async () => {
  const { client } = makeClient({ jwks: () => json({ keys: jwks.map((k) => ({ ...k, kid: 'known' })) }) });
  const token = await generateToken(domain, '<sub>', audience);
  expectRejected(await outcome(client, withKid(token, 'unknown')));
});

test('verifyAccessToken - an unknown kid whose JWKS refetch fails raises AuthServerUnavailableError', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  const { client, state } = makeClient({ jwks: () => json({ keys: jwks.map((k) => ({ ...k, kid: 'known' })) }) });
  const token = await generateToken(domain, '<sub>', audience);
  expectRejected(await outcome(client, withKid(token, 'unknown')));

  // Past the 30 second refetch cooldown the key set is fetched again, and the fetch fails.
  vi.setSystemTime(Date.now() + 31_000);
  state.jwks = () => new Response('down', { status: 503 });
  expectUnavailable(await outcome(client, withKid(token, 'unknown')));
});

test('verifyAccessToken - a cached JWKS keeps serving known keys during an outage', async () => {
  const { client, state, customFetch } = makeClient({});
  const accessToken = await generateToken(domain, '<sub>', audience);
  expect(await outcome(client, accessToken)).toBeUndefined();

  state.jwks = () => new Response('down', { status: 503 });
  const before = customFetch.mock.calls.length;
  expect(await outcome(client, accessToken)).toBeUndefined();
  expect(customFetch.mock.calls.length).toBe(before);
});

test('verifyAccessToken - a JWKS older than its cache lifetime is not served stale during an outage', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  const { client, state } = makeClient({}, { discoveryCache: { ttl: 3600 } });
  const accessToken = await generateToken(domain, '<sub>', audience);
  expect(await outcome(client, accessToken)).toBeUndefined();

  vi.setSystemTime(Date.now() + 11 * 60 * 1000);
  state.jwks = () => new Response('down', { status: 503 });
  expectUnavailable(await outcome(client, accessToken));
});
