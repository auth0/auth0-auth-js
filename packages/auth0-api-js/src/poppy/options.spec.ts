import { afterEach, describe, expect, test, vi } from 'vitest';

import { ApiClient } from '../api-client.js';
import { InvalidConfigurationError, MissingRequiredArgumentError } from '../errors.js';
import type { ApiClientOptions, DomainsResolver, PoppyConfig } from '../types.js';
import { DEFAULT_AGENT_CLIENT_ID_CLAIMS, MAX_URL_LENGTH } from './constants.js';
import { resolvePoppyOptions } from './options.js';
import type { PoppySessionStore } from './session-store.js';

const DOMAIN = 'example.auth0.com';
const ISSUER = 'https://example.auth0.com/';
const AUDIENCE = 'https://api.zepto.example';
const PUBLIC_ORIGIN = 'https://api.zepto.example';
const AGENT_URL = 'https://muse.example/agent.json';
const OTHER_AGENT_URL = 'https://other.example/agent.json';

type Context = Parameters<typeof resolvePoppyOptions>[1];

function errorFrom(action: () => unknown): Error {
  try {
    action();
  } catch (error) {
    return error as Error;
  }
  throw new Error('Expected the action to throw.');
}

/** Expects `InvalidConfigurationError` with the poppy prefix and every fragment in the message. */
function expectInvalid(action: () => unknown, ...fragments: string[]): string {
  const error = errorFrom(action);
  expect(error).toBeInstanceOf(InvalidConfigurationError);
  expect(error.message.startsWith('Invalid poppy configuration: ')).toBe(true);
  for (const fragment of fragments) {
    expect(error.message).toContain(fragment);
  }
  return error.message;
}

/** A valid config for AUDIENCE and ISSUER. `overrides` replaces whole fields, with any value, to make a bad one. */
function configFile(overrides: Record<string, unknown> = {}): PoppyConfig {
  return {
    issuer: ISSUER,
    apis: [{ identifier: AUDIENCE, public_origin: PUBLIC_ORIGIN }],
    agents: [AGENT_URL],
    ...overrides,
  } as PoppyConfig;
}

/** Resolves `poppy` for a client of DOMAIN with the audience AUDIENCE. `poppy` may be any value, to test bad input. */
function resolve(poppy: unknown, context: Context = { defaultDomainUrl: ISSUER }, customFetch?: typeof fetch) {
  const options = { domain: DOMAIN, audience: AUDIENCE, customFetch, poppy } as unknown as ApiClientOptions;
  return resolvePoppyOptions(options, context);
}

describe('resolvePoppyOptions | defaults', () => {
  test('an empty poppy option resolves to the documented defaults', () => {
    const resolved = resolve({});

    expect(resolved).toEqual({
      verifySession: false,
      agentClientIdClaims: ['client_id', 'azp'],
      iatWindowSeconds: 60,
      agentMetadata: {
        fetch: expect.any(Function),
        ttlMs: 600_000,
        maxEntries: 100,
        timeoutMs: 5000,
        maxBytes: 65536,
        allowPrivateAddresses: false,
      },
    });
    expect(resolved.agents).toBeUndefined();
    expect(resolved.sessionStore).toBeUndefined();
    expect(resolved.publicOrigin).toBeUndefined();
    expect(resolved.configIssuer).toBeUndefined();
  });

  test('explicit values replace the defaults', () => {
    const sessionStore = {} as PoppySessionStore;

    const resolved = resolve({
      verifySession: true,
      sessionStore,
      agentClientIdClaims: ['azp'],
      iatWindow: 120,
      agentMetadata: {
        cache: { ttl: 30, maxEntries: 5 },
        timeoutMs: 1500,
        maxBytes: 1024,
        allowPrivateAddresses: true,
      },
    });

    expect(resolved.verifySession).toBe(true);
    expect(resolved.sessionStore).toBe(sessionStore);
    expect(resolved.agentClientIdClaims).toEqual(['azp']);
    expect(resolved.iatWindowSeconds).toBe(120);
    expect(resolved.agentMetadata).toMatchObject({
      ttlMs: 30_000,
      maxEntries: 5,
      timeoutMs: 1500,
      maxBytes: 1024,
      allowPrivateAddresses: true,
    });
  });

  test('a null session store resolves to no session store', () => {
    expect(resolve({ sessionStore: null }).sessionStore).toBeUndefined();
  });
});

describe('resolvePoppyOptions | poppy', () => {
  test.each<[string, unknown]>([
    ['a string', 'yes'],
    ['a number', 42],
    ['true', true],
    ['null', null],
    ['an array', []],
    ['a function', () => ({})],
  ])('throws when poppy is %s instead of an object', (_label, poppy) => {
    expectInvalid(() => resolve(poppy), '"poppy" must be an object');
  });
});

describe('resolvePoppyOptions | verifySession', () => {
  test.each<[string, unknown]>([
    ['a string', 'true'],
    ['a number', 1],
    ['null', null],
    ['an object', {}],
  ])('throws when verifySession is %s', (_label, value) => {
    expectInvalid(() => resolve({ verifySession: value }), '"verifySession" must be a boolean');
  });

  test.each([true, false])('keeps verifySession %s', (value) => {
    expect(resolve({ verifySession: value }).verifySession).toBe(value);
  });
});

describe('resolvePoppyOptions | iatWindow', () => {
  test.each<[string, unknown]>([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
    ['a string', '60'],
    ['null', null],
  ])('throws when iatWindow is %s', (_label, value) => {
    expectInvalid(() => resolve({ iatWindow: value }), '"iatWindow" must be a number');
  });

  test.each([-1, -0.5])('throws when iatWindow is %s', (value) => {
    expectInvalid(() => resolve({ iatWindow: value }), '"iatWindow"', 'non-negative');
  });

  test.each([0, 1, 60, 90.5])('keeps iatWindow %s as the window in seconds', (value) => {
    expect(resolve({ iatWindow: value }).iatWindowSeconds).toBe(value);
  });
});

describe('resolvePoppyOptions | agentClientIdClaims', () => {
  test.each<[string, unknown]>([
    ['an empty array', []],
    ['an empty string in an array', ['']],
    ['a string instead of an array', 'client_id'],
    ['a number in an array', [1]],
    ['null in an array', ['client_id', null]],
    ['null', null],
    ['an object', { 0: 'client_id' }],
  ])('throws for %s', (_label, value) => {
    expectInvalid(
      () => resolve({ agentClientIdClaims: value }),
      '"agentClientIdClaims" must be a non-empty array of non-empty strings'
    );
  });

  test('keeps the order of the claims, in a copy', () => {
    const claims = ['azp', 'client_id', 'cid'];

    const resolved = resolve({ agentClientIdClaims: claims });
    claims.push('sub');
    claims[0] = 'changed';

    expect(resolved.agentClientIdClaims).toEqual(['azp', 'client_id', 'cid']);
  });

  test('resolves the default claims in a copy, never as the shared array', () => {
    const first = resolve({}).agentClientIdClaims;
    const second = resolve({}).agentClientIdClaims;

    expect(first).toEqual(['client_id', 'azp']);
    expect(first).not.toBe(DEFAULT_AGENT_CLIENT_ID_CLAIMS);
    expect(first).not.toBe(second);

    // Even a change made through a cast leaves the shared constant and the next client alone.
    (first as string[]).push('sub');
    expect(DEFAULT_AGENT_CLIENT_ID_CLAIMS).toEqual(['client_id', 'azp']);
    expect(resolve({}).agentClientIdClaims).toEqual(['client_id', 'azp']);
  });
});

describe('resolvePoppyOptions | agents', () => {
  test('resolves to a set of the URLs, in a copy', () => {
    const agents = [AGENT_URL, OTHER_AGENT_URL];

    const resolved = resolve({ agents });
    agents.push('https://late.example/agent.json');
    agents[0] = 'https://changed.example/agent.json';

    expect(resolved.agents).toEqual(new Set([AGENT_URL, OTHER_AGENT_URL]));
  });

  test('an empty list resolves to an empty set, not to no list', () => {
    const resolved = resolve({ agents: [] });

    expect(resolved.agents).toBeInstanceOf(Set);
    expect(resolved.agents?.size).toBe(0);
  });

  test('a repeated URL is kept once', () => {
    expect(resolve({ agents: [AGENT_URL, AGENT_URL] }).agents?.size).toBe(1);
  });

  test.each<[string, unknown]>([
    ['a string', AGENT_URL],
    ['null', null],
    ['an object', { 0: AGENT_URL }],
    ['a Set', new Set([AGENT_URL])],
  ])('throws when agents is %s instead of an array', (_label, agents) => {
    expectInvalid(() => resolve({ agents }), '"agents" must be an array of agent URLs');
  });

  test.each<[string, unknown, string[]]>([
    ['a number', 42, ['"agents[1]" must be a string']],
    ['null', null, ['"agents[1]" must be a string']],
    ['an object', { href: AGENT_URL }, ['"agents[1]" must be a string']],
    ['text that is not a URL', 'muse.example/agent.json', ['"agents[1]" is not a valid URL']],
    ['http', 'http://muse.example/agent.json', ['"agents[1]"', '"http://muse.example/agent.json"', 'https URL']],
    [
      'http in upper case, which is still repeated',
      'HTTP://muse.example/agent.json',
      ['"agents[1]"', '"HTTP://muse.example/agent.json"', 'https URL'],
    ],
    ['credentials', 'https://user:pw@muse.example/agent.json', ['"agents[1]" must not contain a username']],
    ['a fragment', 'https://muse.example/agent.json#top', ['"agents[1]" must not contain a fragment']],
    ['an empty fragment', 'https://muse.example/agent.json#', ['"agents[1]" must not contain a fragment']],
    [
      'a URL over the limit',
      `https://muse.example/${'a'.repeat(MAX_URL_LENGTH)}`,
      [`"agents[1]" is longer than ${MAX_URL_LENGTH} characters`],
    ],
  ])('throws when an entry is %s, and names the entry', (_label, entry, fragments) => {
    expectInvalid(() => resolve({ agents: [AGENT_URL, entry] }), ...fragments);
  });

  test.each<[string, string, string]>([
    ['an upper-case host', 'https://Muse.example/agent.json', 'https://muse.example/agent.json'],
    ['no path', 'https://muse.example', 'https://muse.example/'],
    ['the default port', 'https://muse.example:443/agent.json', 'https://muse.example/agent.json'],
    ['a dot segment', 'https://muse.example/a/../agent.json', 'https://muse.example/agent.json'],
    ['a space', 'https://muse.example/my agent.json', 'https://muse.example/my%20agent.json'],
    ['a Unicode host', 'https://bücher.example/agent.json', 'https://xn--bcher-kva.example/agent.json'],
  ])('shows the canonical form when an entry has %s', (_label, entry, canonical) => {
    expectInvalid(
      () => resolve({ agents: [AGENT_URL, entry] }),
      '"agents[1]"',
      JSON.stringify(entry),
      'is not in canonical form',
      `expected ${JSON.stringify(canonical)}`
    );
  });

  test('accepts the canonical form that the message shows', () => {
    expect(resolve({ agents: ['https://muse.example/'] }).agents).toEqual(new Set(['https://muse.example/']));
  });

  test.each<[string, string]>([
    ['localhost', 'https://localhost:8443/agent.json'],
    ['a name under localhost', 'https://muse.localhost/agent.json'],
    ['a loopback address', 'https://127.0.0.1/agent.json'],
    ['an IPv6 loopback address', 'https://[::1]/agent.json'],
    ['a private address', 'https://192.168.0.5/agent.json'],
    ['a link-local address', 'https://169.254.169.254/agent.json'],
    ['an IPv4-mapped private address, in the form the URL parser writes', 'https://[::ffff:c0a8:1]/agent.json'],
    ['a loopback address with two trailing dots, which the URL parser keeps', 'https://127.0.0.1../agent.json'],
    ['a private address with two trailing dots, which the URL parser keeps', 'https://10.0.0.1../agent.json'],
    ['a name with no dot', 'https://vault/agent.json'],
    ['a name under .local', 'https://muse.local/agent.json'],
    ['a name under .internal', 'https://muse.internal/agent.json'],
    ['a name under .localdomain', 'https://muse.localdomain/agent.json'],
    ['a name under .home.arpa', 'https://muse.home.arpa/agent.json'],
  ])('throws for %s, and says how to allow it for local development', (_label, entry) => {
    expectInvalid(
      () => resolve({ agents: [AGENT_URL, entry] }),
      '"agents[1]"',
      JSON.stringify(entry),
      'agentMetadata.allowPrivateAddresses'
    );
  });

  test.each<[string, string]>([
    ['localhost', 'https://localhost:8443/agent.json'],
    ['a loopback address', 'https://127.0.0.1/agent.json'],
    ['an IPv6 loopback address', 'https://[::1]/agent.json'],
    ['a private address', 'https://192.168.0.5/agent.json'],
    ['a name with no dot', 'https://vault/agent.json'],
    ['a name under .local', 'https://muse.local/agent.json'],
    ['a name under .internal', 'https://muse.internal/agent.json'],
    ['a name under .localdomain', 'https://muse.localdomain/agent.json'],
    ['a name under .home.arpa', 'https://muse.home.arpa/agent.json'],
  ])('accepts %s when allowPrivateAddresses is on', (_label, entry) => {
    const resolved = resolve({ agents: [entry], agentMetadata: { allowPrivateAddresses: true } });

    expect(resolved.agents).toEqual(new Set([entry]));
  });

  test('still checks the shape of an entry when allowPrivateAddresses is on', () => {
    expectInvalid(
      () => resolve({ agents: ['http://localhost/agent.json'], agentMetadata: { allowPrivateAddresses: true } }),
      '"agents[0]"',
      'https URL'
    );
  });

  test('never repeats a secret that was put in the list by mistake', () => {
    const secrets = [
      'https://user:hunter2@muse.example/agent.json',
      'postgres://admin:hunter2@db.internal/app',
      'hunter2.eyJzdWIiOiJoaWRkZW4ifQ.signature',
      'https://muse.example/agent.json#hunter2',
      'http://muse.example/agent.json?token=hunter2',
      'https://Muse.example/agent.json?token=hunter2',
      '//user:hunter2@muse.example/agent.json',
      `https://muse.example/${'hunter2'.repeat(500)}`,
      // A secret in the shape of a URL with an opaque scheme parses as a URL, but it is not http or https.
      'admin:hunter2',
      'user:hunter2',
      'Bearer:hunter2',
      'sk_live:hunter2',
      'http:hunter2',
      'https:hunter2',
    ];

    for (const secret of secrets) {
      const message = expectInvalid(() => resolve({ agents: [secret] }), '"agents[0]"');
      expect(message, secret).not.toContain('hunter2');
      expect(message, secret).not.toContain('eyJzdWIi');
    }
  });

  test('does not echo a value that would be too long for a message', () => {
    const entry = `https://Muse.example/${'a'.repeat(500)}`;

    const message = expectInvalid(() => resolve({ agents: [entry] }), '"agents[0]"');

    expect(message.length).toBeLessThan(500);
  });
});

describe('resolvePoppyOptions | baseUrl', () => {
  test.each<[string, unknown]>([
    ['http', 'http://api.zepto.example'],
    ['a path', 'https://api.zepto.example/v1'],
    ['a query', 'https://api.zepto.example?x=1'],
    ['a fragment', 'https://api.zepto.example#top'],
    ['credentials', 'https://user:pw@api.zepto.example'],
    ['no scheme', 'api.zepto.example'],
    ['an empty string', ''],
    ['a number', 42],
    ['null', null],
  ])('throws for %s', (_label, baseUrl) => {
    expectInvalid(() => resolve({ baseUrl }), '"baseUrl"', 'must be an https origin');
  });

  test('shows the origin to write when the value only has too much', () => {
    expectInvalid(
      () => resolve({ baseUrl: 'https://api.zepto.example/v1' }),
      '"baseUrl" ("https://api.zepto.example/v1")',
      'Use "https://api.zepto.example"'
    );
  });

  test('does not repeat credentials, a query or a value that is not an http(s) URL', () => {
    const secrets = [
      'https://user:hunter2@api.zepto.example/v1',
      'https://api.zepto.example/v1?token=hunter2',
      'admin:hunter2',
      'user:hunter2',
      'Bearer:hunter2',
      'https:hunter2',
    ];

    for (const baseUrl of secrets) {
      const message = expectInvalid(() => resolve({ baseUrl }), '"baseUrl"');

      expect(message, baseUrl).not.toContain('hunter2');
    }
  });

  test.each<[string, string, string]>([
    ['a host', 'https://api.zepto.example', 'https://api.zepto.example'],
    ['a trailing slash', 'https://api.zepto.example/', 'https://api.zepto.example'],
    ['an upper-case host', 'https://API.Zepto.example', 'https://api.zepto.example'],
    ['the default port', 'https://api.zepto.example:443/', 'https://api.zepto.example'],
    ['a port that is not the default one', 'https://api.zepto.example:8443', 'https://api.zepto.example:8443'],
    ['localhost', 'https://localhost:3000', 'https://localhost:3000'],
  ])('stores the origin of a baseUrl with %s', (_label, baseUrl, origin) => {
    expect(resolve({ baseUrl }).publicOrigin).toBe(origin);
  });
});

describe('resolvePoppyOptions | agentMetadata', () => {
  test.each<[string, unknown]>([
    ['a string', 'fetch'],
    ['null', null],
    ['an array', []],
    ['a function', () => ({})],
  ])('throws when agentMetadata is %s instead of an object', (_label, agentMetadata) => {
    expectInvalid(() => resolve({ agentMetadata }), '"agentMetadata" must be an object');
  });

  test.each<[string, unknown]>([
    ['a string', 'fetch'],
    ['null', null],
    ['an object', {}],
  ])('throws when fetch is %s instead of a function', (_label, value) => {
    expectInvalid(() => resolve({ agentMetadata: { fetch: value } }), '"agentMetadata.fetch" must be a function');
  });

  // AbortSignal.timeout throws for a fraction, and for a delay over 2^31 - 1 it throws or runs 1 millisecond. The
  // fetcher passes the value on as it is, so the range is checked here.
  test.each<[string, unknown]>([
    ['0', 0],
    ['0.5', 0.5],
    ['a number with a fraction', 250.5],
    ['negative', -1],
    ['one more than a timer can hold', 2_147_483_648],
    ['more than 32 bits', 1e12],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['negative Infinity', Number.NEGATIVE_INFINITY],
    ['a string', '5000'],
    ['a bigint', 5000n],
    ['a boolean', true],
    ['an object', {}],
  ])('throws when timeoutMs is %s', (_label, value) => {
    const message = expectInvalid(
      () => resolve({ agentMetadata: { timeoutMs: value } }),
      '"agentMetadata.timeoutMs" must be a whole number of milliseconds from 1 to 2147483647'
    );
    // The range is in the message once, and the value is not repeated.
    expect(message).toBe(
      'Invalid poppy configuration: ' +
        '"agentMetadata.timeoutMs" must be a whole number of milliseconds from 1 to 2147483647'
    );
  });

  test.each([1, 2, 1500, 60_000, 2_147_483_646, 2_147_483_647])('keeps timeoutMs %s', (timeoutMs) => {
    expect(resolve({ agentMetadata: { timeoutMs } }).agentMetadata.timeoutMs).toBe(timeoutMs);
  });

  test.each<[string, unknown]>([
    ['0', 0],
    ['negative', -1],
    ['not a whole number', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['a string', '1024'],
  ])('throws when maxBytes is %s', (_label, value) => {
    expectInvalid(
      () => resolve({ agentMetadata: { maxBytes: value } }),
      '"agentMetadata.maxBytes" must be a whole number',
      'greater than 0'
    );
  });

  test.each([1, 1024, 1_048_576])('keeps maxBytes %s', (maxBytes) => {
    expect(resolve({ agentMetadata: { maxBytes } }).agentMetadata.maxBytes).toBe(maxBytes);
  });

  test.each<[string, unknown]>([
    ['a string', 'yes'],
    ['a number', 1],
    ['null', null],
  ])('throws when allowPrivateAddresses is %s', (_label, value) => {
    expectInvalid(
      () => resolve({ agentMetadata: { allowPrivateAddresses: value } }),
      '"agentMetadata.allowPrivateAddresses" must be a boolean'
    );
  });

  test.each<[string, unknown]>([
    ['a string', 'ttl'],
    ['null', null],
    ['an array', []],
  ])('throws when cache is %s instead of an object', (_label, cache) => {
    expectInvalid(() => resolve({ agentMetadata: { cache } }), '"agentMetadata.cache" must be an object');
  });

  test.each<[string, unknown]>([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['a string', '600'],
  ])('throws when cache.ttl is %s', (_label, ttl) => {
    expectInvalid(() => resolve({ agentMetadata: { cache: { ttl } } }), '"agentMetadata.cache.ttl" must be a number');
  });

  test('throws when cache.ttl is negative', () => {
    expectInvalid(
      () => resolve({ agentMetadata: { cache: { ttl: -1 } } }),
      '"agentMetadata.cache.ttl" must be a non-negative number'
    );
  });

  test.each<[string, unknown]>([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['a string', '100'],
  ])('throws when cache.maxEntries is %s', (_label, maxEntries) => {
    expectInvalid(
      () => resolve({ agentMetadata: { cache: { maxEntries } } }),
      '"agentMetadata.cache.maxEntries" must be a number'
    );
  });

  test('throws when cache.maxEntries is negative', () => {
    expectInvalid(
      () => resolve({ agentMetadata: { cache: { maxEntries: -1 } } }),
      '"agentMetadata.cache.maxEntries" must be a non-negative number'
    );
  });

  test('accepts the same cache values as discoveryCache, 0 included', () => {
    const resolved = resolve({ agentMetadata: { cache: { ttl: 0, maxEntries: 0 } } });

    expect(resolved.agentMetadata.ttlMs).toBe(0);
    expect(resolved.agentMetadata.maxEntries).toBe(0);
  });

  test('converts the cache ttl from seconds to milliseconds', () => {
    expect(resolve({ agentMetadata: { cache: { ttl: 1.5 } } }).agentMetadata.ttlMs).toBe(1500);
  });

  test('keeps a default for the cache value that is not set', () => {
    expect(resolve({ agentMetadata: { cache: { ttl: 10 } } }).agentMetadata).toMatchObject({
      ttlMs: 10_000,
      maxEntries: 100,
    });
    expect(resolve({ agentMetadata: { cache: { maxEntries: 7 } } }).agentMetadata).toMatchObject({
      ttlMs: 600_000,
      maxEntries: 7,
    });
  });

  // `discoveryCache` reads these with `??`, so a null is the same as a value that is not set.
  test.each<[string, Record<string, unknown>, Record<string, number>]>([
    ['cache.ttl', { cache: { ttl: null } }, { ttlMs: 600_000 }],
    ['cache.maxEntries', { cache: { maxEntries: null } }, { maxEntries: 100 }],
    ['timeoutMs', { timeoutMs: null }, { timeoutMs: 5000 }],
    ['maxBytes', { maxBytes: null }, { maxBytes: 65536 }],
  ])('resolves a null %s to its default', (_label, agentMetadata, expected) => {
    expect(resolve({ agentMetadata }).agentMetadata).toMatchObject(expected);
  });

  test('resolves a null next to a valid value, and keeps the valid one', () => {
    const resolved = resolve({
      agentMetadata: { cache: { ttl: null, maxEntries: 7 }, timeoutMs: 1500, maxBytes: null },
    });

    expect(resolved.agentMetadata).toMatchObject({ ttlMs: 600_000, maxEntries: 7, timeoutMs: 1500, maxBytes: 65536 });
  });

  test('still refuses a null for the options that are not numbers or that discoveryCache has no equivalent for', () => {
    expectInvalid(() => resolve({ iatWindow: null }), '"iatWindow" must be a number');
    expectInvalid(() => resolve({ agentMetadata: { fetch: null } }), '"agentMetadata.fetch" must be a function');
    expectInvalid(
      () => resolve({ agentMetadata: { allowPrivateAddresses: null } }),
      '"agentMetadata.allowPrivateAddresses" must be a boolean'
    );
    expectInvalid(() => resolve({ agentMetadata: { cache: null } }), '"agentMetadata.cache" must be an object');
  });
});

describe('resolvePoppyOptions | agentMetadata.fetch', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const url = 'https://muse.example/agent.json';
  const init = { method: 'GET', redirect: 'manual' } as const;

  test('is the global fetch by default, looked up when it is called', async () => {
    const resolved = resolve({});
    const globalFetch = vi.fn(async () => new Response('{}'));
    vi.stubGlobal('fetch', globalFetch);

    await resolved.agentMetadata.fetch(url, init);

    expect(globalFetch).toHaveBeenCalledTimes(1);
    expect(globalFetch).toHaveBeenCalledWith(url, init);
  });

  test('is the customFetch of the client when agentMetadata.fetch is not set', async () => {
    const customFetch = vi.fn(async () => new Response('{}'));
    const globalFetch = vi.fn(async () => new Response('{}'));
    vi.stubGlobal('fetch', globalFetch);

    const resolved = resolve({}, undefined, customFetch);
    await resolved.agentMetadata.fetch(url, init);

    expect(customFetch).toHaveBeenCalledWith(url, init);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test('is agentMetadata.fetch before the customFetch of the client', async () => {
    const customFetch = vi.fn(async () => new Response('{}'));
    const metadataFetch = vi.fn(async () => new Response('{}'));

    const resolved = resolve({ agentMetadata: { fetch: metadataFetch } }, undefined, customFetch);
    await resolved.agentMetadata.fetch(url, init);

    expect(metadataFetch).toHaveBeenCalledWith(url, init);
    expect(customFetch).not.toHaveBeenCalled();
  });

  test.each<[string, 'agentMetadata' | 'customFetch']>([
    ['agentMetadata.fetch', 'agentMetadata'],
    ['customFetch', 'customFetch'],
  ])('calls %s as a plain function, never as a method of the options', async (_label, source) => {
    // Workers can throw "Illegal invocation" when the global fetch is called with another receiver.
    const given = vi.fn(async () => new Response('{}'));

    const resolved =
      source === 'agentMetadata' ? resolve({ agentMetadata: { fetch: given } }) : resolve({}, undefined, given);
    await resolved.agentMetadata.fetch(url, init);

    expect(given.mock.contexts).toEqual([undefined]);
  });
});

describe('resolvePoppyOptions | config', () => {
  test('resolves the issuer, the public origin and the agents from the config', () => {
    const resolved = resolve({ config: configFile() });

    expect(resolved.configIssuer).toBe(ISSUER);
    expect(resolved.publicOrigin).toBe(PUBLIC_ORIGIN);
    expect(resolved.agents).toEqual(new Set([AGENT_URL]));
  });

  test('keeps the issuer exactly as written, trailing slash included', () => {
    const resolved = resolve({ config: configFile({ issuer: 'https://login.example.com/' }) }, { domains: () => [] });

    expect(resolved.configIssuer).toBe('https://login.example.com/');
  });

  test('stores the origin of the public_origin of the apis entry for the audience', () => {
    const config = configFile({
      apis: [
        { identifier: 'https://other.example', public_origin: 'https://other.example' },
        { identifier: AUDIENCE, public_origin: 'https://API.Zepto.example:443/' },
      ],
    });

    expect(resolve({ config }).publicOrigin).toBe('https://api.zepto.example');
  });

  test('explicit agents and baseUrl win over the config', () => {
    const resolved = resolve({
      config: configFile({ agents: [AGENT_URL] }),
      agents: [OTHER_AGENT_URL],
      baseUrl: 'https://public.zepto.example',
    });

    expect(resolved.agents).toEqual(new Set([OTHER_AGENT_URL]));
    expect(resolved.publicOrigin).toBe('https://public.zepto.example');
  });

  test('an explicit empty agents list wins over the agents of the config', () => {
    expect(resolve({ config: configFile(), agents: [] }).agents?.size).toBe(0);
  });

  test('a config without agents leaves the agents unset', () => {
    expect(resolve({ config: configFile({ agents: undefined }) }).agents).toBeUndefined();
  });

  test('a config with an empty agents list resolves to an empty set', () => {
    expect(resolve({ config: configFile({ agents: [] }) }).agents?.size).toBe(0);
  });

  test('mutating the agents array of the config after resolving changes nothing', () => {
    const config = configFile({ agents: [AGENT_URL] });

    const resolved = resolve({ config });
    config.agents?.push(OTHER_AGENT_URL);
    if (config.agents) config.agents[0] = 'https://changed.example/agent.json';

    expect(resolved.agents).toEqual(new Set([AGENT_URL]));
  });

  test.each<[string, unknown]>([
    ['a string', 'auth0-poppy.json'],
    ['null', null],
    ['an array', []],
    ['a number', 42],
  ])('throws when config is %s instead of an object', (_label, config) => {
    expectInvalid(() => resolve({ config }), '"config" must be an object');
  });

  test.each<[string, unknown]>([
    ['missing', undefined],
    ['http', 'http://example.auth0.com/'],
    ['a path', 'https://example.auth0.com/tenant/'],
    ['a query', 'https://example.auth0.com/?x=1'],
    ['credentials', 'https://user:pw@example.auth0.com/'],
    ['not a URL', 'example.auth0.com'],
    ['a number', 42],
    ['an empty string', ''],
  ])('throws when the issuer is %s', (_label, issuer) => {
    expectInvalid(() => resolve({ config: configFile({ issuer }) }), '"config.issuer"', 'must be an https origin');
  });

  test('does not repeat a secret-shaped issuer or public_origin', () => {
    for (const secret of ['admin:hunter2', 'user:hunter2', 'Bearer:hunter2', 'https:hunter2']) {
      const configs = [
        configFile({ issuer: secret }),
        configFile({ apis: [{ identifier: AUDIENCE, public_origin: secret }] }),
      ];

      for (const config of configs) {
        const message = expectInvalid(() => resolve({ config }), '"config.');

        expect(message, secret).not.toContain('hunter2');
      }
    }
  });

  describe('the canonical issuer', () => {
    // Auth0 writes the issuer as `origin` and a trailing slash. The `aud` of a Session JWT is compared with it
    // character by character, so any other way of writing it would match no Session.
    const domainsFunction: DomainsResolver = () => ['auth.zepto.example'];

    test.each<[string, string, string]>([
      ['no trailing slash', 'https://auth.zepto.example', 'https://auth.zepto.example/'],
      ['an upper-case host', 'https://AUTH.zepto.example/', 'https://auth.zepto.example/'],
      ['a mixed-case host', 'https://Auth.Zepto.example/', 'https://auth.zepto.example/'],
      ['the default port', 'https://auth.zepto.example:443/', 'https://auth.zepto.example/'],
      ['an upper-case host and no trailing slash', 'https://AUTH.zepto.example', 'https://auth.zepto.example/'],
      ['the default port and no trailing slash', 'https://auth.zepto.example:443', 'https://auth.zepto.example/'],
      [
        'a port that is not the default one, and no trailing slash',
        'https://auth.zepto.example:8443',
        'https://auth.zepto.example:8443/',
      ],
    ])('throws for an issuer with %s, also when domains is a function', (_label, issuer, canonical) => {
      expectInvalid(
        () => resolve({ config: configFile({ issuer }) }, { domains: domainsFunction }),
        `"config.issuer" must be the canonical issuer ${JSON.stringify(canonical)}`,
        `not ${JSON.stringify(issuer)}`,
        'lower-case host',
        'trailing slash',
        'character by character'
      );
    });

    test.each<[string, Context]>([
      ['a domains function', { domains: domainsFunction }],
      ['a list of domains', { domains: ['https://auth.zepto.example/'] }],
      ['the issuer of domain', { defaultDomainUrl: 'https://auth.zepto.example/' }],
      ['no domain at all', {}],
    ])('is checked before the issuer is matched with %s', (_label, context) => {
      expectInvalid(
        () => resolve({ config: configFile({ issuer: 'https://auth.zepto.example' }) }, context),
        '"config.issuer" must be the canonical issuer "https://auth.zepto.example/"'
      );
    });

    test.each<[string, string]>([
      ['a host', 'https://auth.zepto.example/'],
      ['a host and a port that is not the default one', 'https://auth.zepto.example:8443/'],
      ['an IPv6 address', 'https://[::1]:3000/'],
      ['localhost', 'https://localhost:3000/'],
    ])('accepts an issuer with %s, also when domains is a function', (_label, issuer) => {
      const resolved = resolve({ config: configFile({ issuer }) }, { domains: domainsFunction });

      expect(resolved.configIssuer).toBe(issuer);
    });

    test('does not repeat an issuer that is too long for a message', () => {
      const issuer = `https://${'a'.repeat(300)}.example`;

      const message = expectInvalid(
        () => resolve({ config: configFile({ issuer }) }),
        '"config.issuer" must be the canonical'
      );

      expect(message).not.toContain('a'.repeat(250));
    });
  });

  test.each<[string, unknown]>([
    ['missing', undefined],
    ['empty', []],
    ['a string', 'apis'],
    ['an object', { 0: { identifier: AUDIENCE, public_origin: PUBLIC_ORIGIN } }],
    ['null', null],
  ])('throws when apis is %s', (_label, apis) => {
    expectInvalid(() => resolve({ config: configFile({ apis }) }), '"config.apis" must be a non-empty array');
  });

  test('throws when no apis entry has the audience as its identifier, and names the audience', () => {
    const config = configFile({ apis: [{ identifier: 'https://other.example', public_origin: PUBLIC_ORIGIN }] });

    expectInvalid(
      () => resolve({ config }),
      '"config.apis" has no entry with the identifier "https://api.zepto.example"',
      'the audience',
      '"https://other.example"'
    );
  });

  test('shows that an identifier with a trailing slash is not the audience', () => {
    const config = configFile({ apis: [{ identifier: `${AUDIENCE}/`, public_origin: PUBLIC_ORIGIN }] });

    expectInvalid(() => resolve({ config }), `"${AUDIENCE}"`, `"${AUDIENCE}/"`);
  });

  test('lists only the first identifiers when the config has many', () => {
    const apis = Array.from({ length: 12 }, (_value, index) => ({
      identifier: `https://api${index}.example`,
      public_origin: `https://api${index}.example`,
    }));

    const message = expectInvalid(() => resolve({ config: configFile({ apis }) }), '"config.apis" has no entry');

    expect(message).toContain('"https://api4.example"');
    expect(message).not.toContain('"https://api5.example"');
    expect(message).toContain('and 7 more');
  });

  test('throws, and does not crash, when the apis array has entries that are not objects', () => {
    expectInvalid(() => resolve({ config: configFile({ apis: [null, 42, 'x'] }) }), '"config.apis" has no entry');
  });

  test.each<[string, unknown]>([
    ['missing', undefined],
    ['http', 'http://api.zepto.example'],
    ['a path', 'https://api.zepto.example/v1'],
    ['credentials', 'https://user:pw@api.zepto.example'],
    ['a number', 42],
  ])('throws when the public_origin of the matching entry is %s', (_label, publicOrigin) => {
    const config = configFile({
      apis: [
        { identifier: 'https://other.example', public_origin: 'https://other.example' },
        { identifier: AUDIENCE, public_origin: publicOrigin },
      ],
    });

    expectInvalid(() => resolve({ config }), '"config.apis[1].public_origin"', 'must be an https origin');
  });

  test('does not read the public_origin of an entry for another audience', () => {
    const config = configFile({
      apis: [
        { identifier: 'https://other.example', public_origin: 'not a url' },
        { identifier: AUDIENCE, public_origin: PUBLIC_ORIGIN },
      ],
    });

    expect(resolve({ config }).publicOrigin).toBe(PUBLIC_ORIGIN);
  });

  test('does not read the public_origin of the matching entry when baseUrl is set', () => {
    const config = configFile({ apis: [{ identifier: AUDIENCE, public_origin: 'not a url' }] });

    expect(resolve({ config, baseUrl: 'https://public.zepto.example' }).publicOrigin).toBe(
      'https://public.zepto.example'
    );
  });

  test('throws when the agents of the config are not an array', () => {
    expectInvalid(
      () => resolve({ config: configFile({ agents: AGENT_URL }) }),
      '"config.agents" must be an array of agent URLs'
    );
  });

  test('throws when an entry of the config agents is not an agent URL, and names it', () => {
    expectInvalid(
      () => resolve({ config: configFile({ agents: [AGENT_URL, 'https://Muse.example/agent.json'] }) }),
      '"config.agents[1]"',
      'is not in canonical form',
      'expected "https://muse.example/agent.json"'
    );
  });

  test('throws when an entry of the config agents is on a private address, unless that is allowed', () => {
    const config = configFile({ agents: ['https://localhost:8443/agent.json'] });

    expectInvalid(() => resolve({ config }), '"config.agents[0]"', 'agentMetadata.allowPrivateAddresses');
    expect(
      resolve({ config, agentMetadata: { allowPrivateAddresses: true } }).agents?.has(
        'https://localhost:8443/agent.json'
      )
    ).toBe(true);
  });

  test('does not read the agents of the config when agents is set', () => {
    const config = configFile({ agents: 'not a list' });

    expect(resolve({ config, agents: [OTHER_AGENT_URL] }).agents).toEqual(new Set([OTHER_AGENT_URL]));
  });
});

describe('resolvePoppyOptions | issuer of the config and the domain', () => {
  test('passes when the issuer is the issuer of domain, trailing slash included', () => {
    expect(() => resolve({ config: configFile({ issuer: ISSUER }) }, { defaultDomainUrl: ISSUER })).not.toThrow();
  });

  test('throws when the issuer has no trailing slash, and explains that it must match exactly', () => {
    expectInvalid(
      () => resolve({ config: configFile({ issuer: 'https://example.auth0.com' }) }, { defaultDomainUrl: ISSUER }),
      `"config.issuer" must be the canonical issuer "${ISSUER}"`,
      'not "https://example.auth0.com"',
      'trailing slash',
      'character by character'
    );
  });

  test('throws when the issuer is written in upper case, and shows the canonical issuer', () => {
    expectInvalid(
      () => resolve({ config: configFile({ issuer: 'https://Example.auth0.com/' }) }, { defaultDomainUrl: ISSUER }),
      `"config.issuer" must be the canonical issuer "${ISSUER}"`
    );
  });

  test.each<[string, string]>([
    ['another host', 'https://other.auth0.com/'],
    ['a port', 'https://example.auth0.com:8443/'],
  ])('throws when the issuer has %s than the domain', (_label, issuer) => {
    expectInvalid(
      () => resolve({ config: configFile({ issuer }) }, { defaultDomainUrl: ISSUER }),
      `"config.issuer" (${JSON.stringify(issuer)})`,
      `expected "${ISSUER}"`
    );
  });

  test('with a list of domains, passes when the issuer is one of them', () => {
    const context: Context = { domains: ['https://a.example.com/', 'https://b.example.com/'] };

    expect(() => resolve({ config: configFile({ issuer: 'https://b.example.com/' }) }, context)).not.toThrow();
  });

  test('with a list of domains, throws when the issuer is none of them, and lists them', () => {
    const context: Context = { domains: ['https://a.example.com/', 'https://b.example.com/'] };

    expectInvalid(
      () => resolve({ config: configFile({ issuer: 'https://c.example.com/' }) }, context),
      '"config.issuer" ("https://c.example.com/")',
      '"domains"',
      'trailing slash',
      '"https://a.example.com/"',
      '"https://b.example.com/"'
    );
  });

  test('with a list of domains, the issuer of domain is not enough', () => {
    const context: Context = { defaultDomainUrl: ISSUER, domains: ['https://a.example.com/'] };

    expectInvalid(() => resolve({ config: configFile({ issuer: ISSUER }) }, context), '"config.issuer"', '"domains"');
  });

  test('with a list of domains, shortens the list of expected issuers', () => {
    const domains = Array.from({ length: 9 }, (_value, index) => `https://d${index}.example.com/`);

    const message = expectInvalid(
      () => resolve({ config: configFile({ issuer: 'https://c.example.com/' }) }, { domains }),
      '"config.issuer"'
    );

    expect(message).toContain('"https://d4.example.com/"');
    expect(message).not.toContain('"https://d5.example.com/"');
    expect(message).toContain('and 4 more');
  });

  test('with a domains function, does not match the issuer with a domain, as the domains are known per request', () => {
    const domains: DomainsResolver = () => ['a.example.com'];

    expect(() =>
      resolve({ config: configFile({ issuer: 'https://unrelated.example/' }) }, { defaultDomainUrl: ISSUER, domains })
    ).not.toThrow();
  });

  test('has nothing to compare the issuer with when the context has no domain', () => {
    expect(() => resolve({ config: configFile({ issuer: 'https://unrelated.example/' }) }, {})).not.toThrow();
  });

  test('does not check the issuer when there is no config', () => {
    expect(() => resolve({}, { defaultDomainUrl: ISSUER })).not.toThrow();
  });
});

describe('ApiClient | the poppy option', () => {
  const clientOptions = { domain: DOMAIN, audience: AUDIENCE };

  test('constructs without the poppy option, as it always did', () => {
    expect(() => new ApiClient(clientOptions)).not.toThrow();
    expect(() => new ApiClient({ ...clientOptions, poppy: undefined })).not.toThrow();
  });

  test('constructs with an empty poppy option', () => {
    expect(() => new ApiClient({ ...clientOptions, poppy: {} })).not.toThrow();
  });

  test('constructs with a complete poppy option', () => {
    expect(
      () =>
        new ApiClient({
          ...clientOptions,
          poppy: {
            config: configFile(),
            verifySession: true,
            agents: [AGENT_URL],
            agentClientIdClaims: ['client_id'],
            iatWindow: 30,
            baseUrl: PUBLIC_ORIGIN,
            agentMetadata: { timeoutMs: 1000, maxBytes: 2048, cache: { ttl: 60, maxEntries: 10 } },
          },
        })
    ).not.toThrow();
  });

  test.each<[string, unknown, string]>([
    ['poppy is not an object', 'on', '"poppy" must be an object'],
    ['poppy is null', null, '"poppy" must be an object'],
    ['verifySession is not a boolean', { verifySession: 'yes' }, '"verifySession" must be a boolean'],
    ['an agent URL is not canonical', { agents: ['https://Muse.example/x'] }, '"agents[0]"'],
    ['baseUrl has a path', { baseUrl: 'https://api.zepto.example/v1' }, '"baseUrl"'],
  ])('throws InvalidConfigurationError when %s', (_label, poppy, fragment) => {
    expectInvalid(() => new ApiClient({ ...clientOptions, poppy } as unknown as ApiClientOptions), fragment);
  });

  test('checks the audience before the poppy option', () => {
    expect(() => new ApiClient({ domain: DOMAIN, audience: '', poppy: 'on' } as unknown as ApiClientOptions)).toThrow(
      MissingRequiredArgumentError
    );
  });

  test('throws when the config issuer has no trailing slash and the domain is example.auth0.com', () => {
    expectInvalid(
      () => new ApiClient({ ...clientOptions, poppy: { config: configFile({ issuer: 'https://example.auth0.com' }) } }),
      '"config.issuer" must be the canonical issuer "https://example.auth0.com/"',
      'trailing slash'
    );
  });

  test('passes when the config issuer is the issuer of the domain', () => {
    expect(() => new ApiClient({ ...clientOptions, poppy: { config: configFile() } })).not.toThrow();
  });

  test('throws when the audience is not in the config', () => {
    expectInvalid(
      () => new ApiClient({ domain: DOMAIN, audience: 'https://another.example', poppy: { config: configFile() } }),
      '"config.apis"',
      '"https://another.example"'
    );
  });

  test('compares the config issuer with the normalized domain', () => {
    expect(
      () =>
        new ApiClient({
          domain: 'https://EXAMPLE.auth0.com',
          audience: AUDIENCE,
          poppy: { config: configFile() },
        })
    ).not.toThrow();
  });

  test('with domains, passes when the issuer is one of them', () => {
    expect(
      () =>
        new ApiClient({
          domains: ['a.example.com', 'b.example.com'],
          audience: AUDIENCE,
          poppy: { config: configFile({ issuer: 'https://b.example.com/' }) },
        })
    ).not.toThrow();
  });

  test('with domains, compares the issuer with the normalized domains', () => {
    expect(
      () =>
        new ApiClient({
          domains: ['A.Example.com', 'https://b.example.com'],
          audience: AUDIENCE,
          poppy: { config: configFile({ issuer: 'https://a.example.com/' }) },
        })
    ).not.toThrow();
  });

  test('with domains, throws when the issuer is none of them', () => {
    expectInvalid(
      () =>
        new ApiClient({
          domains: ['a.example.com', 'b.example.com'],
          audience: AUDIENCE,
          poppy: { config: configFile({ issuer: 'https://c.example.com/' }) },
        }),
      '"config.issuer"',
      '"https://a.example.com/"'
    );
  });

  test('with domain and domains, the issuer must be one of the domains', () => {
    const options = { domain: DOMAIN, domains: ['a.example.com'], audience: AUDIENCE };

    expectInvalid(
      () => new ApiClient({ ...options, poppy: { config: configFile({ issuer: ISSUER }) } }),
      '"config.issuer"'
    );
    expect(
      () => new ApiClient({ ...options, poppy: { config: configFile({ issuer: 'https://a.example.com/' }) } })
    ).not.toThrow();
  });

  test('with a domains function, does not match the issuer with a domain', () => {
    expect(
      () =>
        new ApiClient({
          domains: () => ['a.example.com'],
          audience: AUDIENCE,
          poppy: { config: configFile({ issuer: 'https://unrelated.example/' }) },
        })
    ).not.toThrow();
  });

  test.each([
    ['no trailing slash', 'https://auth.zepto.example'],
    ['an upper-case host', 'https://AUTH.zepto.example/'],
    ['the default port', 'https://auth.zepto.example:443/'],
  ])('with a domains function, still throws for an issuer with %s', (_label, issuer) => {
    expectInvalid(
      () =>
        new ApiClient({
          domains: () => ['auth.zepto.example'],
          audience: AUDIENCE,
          poppy: { config: configFile({ issuer }) },
        }),
      '"config.issuer" must be the canonical issuer "https://auth.zepto.example/"'
    );
  });
});
