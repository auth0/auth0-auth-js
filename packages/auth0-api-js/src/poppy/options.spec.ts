import { afterEach, describe, expect, test, vi } from 'vitest';

import { ApiClient } from '../api-client.js';
import { InvalidConfigurationError, MissingRequiredArgumentError } from '../errors.js';
import type { ApiClientOptions } from '../types.js';
import { MAX_URL_LENGTH } from './constants.js';
import { resolvePoppyOptions } from './options.js';
import type { PoppySessionStore } from './session-store.js';

const DOMAIN = 'example.auth0.com';
const AUDIENCE = 'https://api.zepto.example';
const PUBLIC_ORIGIN = 'https://api.zepto.example';
const AGENT_URL = 'https://muse.example/agent.json';
const OTHER_AGENT_URL = 'https://other.example/agent.json';

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

/** Resolves `poppy` for a client of DOMAIN with the audience AUDIENCE. `poppy` may be any value, to test bad input. */
function resolve(poppy: unknown, customFetch?: typeof fetch) {
  const options = { domain: DOMAIN, audience: AUDIENCE, customFetch, poppy } as unknown as ApiClientOptions;
  return resolvePoppyOptions(options);
}

describe('resolvePoppyOptions | defaults', () => {
  test('an empty poppy option resolves to the documented defaults', () => {
    const resolved = resolve({});

    expect(resolved).toEqual({
      verifySession: false,
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
  });

  test('explicit values replace the defaults', () => {
    const sessionStore = {} as PoppySessionStore;

    const resolved = resolve({
      verifySession: true,
      sessionStore,
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

describe('resolvePoppyOptions | publicOrigin', () => {
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
  ])('throws for %s', (_label, publicOrigin) => {
    expectInvalid(() => resolve({ publicOrigin }), '"publicOrigin"', 'must be an https origin');
  });

  test('shows the origin to write when the value only has too much', () => {
    expectInvalid(
      () => resolve({ publicOrigin: 'https://api.zepto.example/v1' }),
      '"publicOrigin" ("https://api.zepto.example/v1")',
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

    for (const publicOrigin of secrets) {
      const message = expectInvalid(() => resolve({ publicOrigin }), '"publicOrigin"');

      expect(message, publicOrigin).not.toContain('hunter2');
    }
  });

  test.each<[string, string, string]>([
    ['a host', 'https://api.zepto.example', 'https://api.zepto.example'],
    ['a trailing slash', 'https://api.zepto.example/', 'https://api.zepto.example'],
    ['an upper-case host', 'https://API.Zepto.example', 'https://api.zepto.example'],
    ['the default port', 'https://api.zepto.example:443/', 'https://api.zepto.example'],
    ['a port that is not the default one', 'https://api.zepto.example:8443', 'https://api.zepto.example:8443'],
    ['localhost', 'https://localhost:3000', 'https://localhost:3000'],
  ])('stores the origin of a publicOrigin with %s', (_label, publicOrigin, origin) => {
    expect(resolve({ publicOrigin }).publicOrigin).toBe(origin);
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

    const resolved = resolve({}, customFetch);
    await resolved.agentMetadata.fetch(url, init);

    expect(customFetch).toHaveBeenCalledWith(url, init);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test('is agentMetadata.fetch before the customFetch of the client', async () => {
    const customFetch = vi.fn(async () => new Response('{}'));
    const metadataFetch = vi.fn(async () => new Response('{}'));

    const resolved = resolve({ agentMetadata: { fetch: metadataFetch } }, customFetch);
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
      source === 'agentMetadata' ? resolve({ agentMetadata: { fetch: given } }) : resolve({}, given);
    await resolved.agentMetadata.fetch(url, init);

    expect(given.mock.contexts).toEqual([undefined]);
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
            verifySession: true,
            agents: [AGENT_URL],
            iatWindow: 30,
            publicOrigin: PUBLIC_ORIGIN,
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
    ['publicOrigin has a path', { publicOrigin: 'https://api.zepto.example/v1' }, '"publicOrigin"'],
  ])('throws InvalidConfigurationError when %s', (_label, poppy, fragment) => {
    expectInvalid(() => new ApiClient({ ...clientOptions, poppy } as unknown as ApiClientOptions), fragment);
  });

  test('checks the audience before the poppy option', () => {
    expect(() => new ApiClient({ domain: DOMAIN, audience: '', poppy: 'on' } as unknown as ApiClientOptions)).toThrow(
      MissingRequiredArgumentError
    );
  });
});
