import { describe, expect, expectTypeOf, test, vi } from 'vitest';
import { InvalidConfigurationError } from '../errors.js';
import { ServerClient } from '../server-client.js';
import type { ServerClientOptions, UserClaims } from '../types.js';
import { POPPY_CLIENT_ID, POPPY_DOMAIN, POPPY_ISSUER, createPoppyConfig } from '../test-utils/poppy.js';
import { resolvePoppyOptions } from './options.js';
import { ServerPoppyClient } from './server-poppy-client.js';
import type { PoppyOptions } from './types.js';

const PREFIX = 'Invalid poppy configuration: ';

// The guest store is a stub: nothing in these tests reads or writes a guest.
const stubStore = () => ({ get: vi.fn(), set: vi.fn(), delete: vi.fn() });

// A ServerClient configuration without the `poppy` option.
const baseOptions = (): ServerClientOptions => ({
  domain: POPPY_DOMAIN,
  clientId: POPPY_CLIENT_ID,
  clientSecret: 'client-secret',
  transactionStore: stubStore(),
  stateStore: { ...stubStore(), deleteByLogoutToken: vi.fn() },
});

type Parts = { config?: Record<string, unknown>; poppy?: Record<string, unknown> };

// The `poppy` option. `config` replaces members of the valid config, and `poppy` replaces members of the option.
const poppyOptions = (parts: Parts = {}): PoppyOptions =>
  ({ config: { ...createPoppyConfig(), ...parts.config }, guestStore: stubStore(), ...parts.poppy }) as PoppyOptions;

const validApi = createPoppyConfig().apis![0]!;

// A list with a hole after a valid entry. `every` skips holes, so a check that only uses `every` accepts it.
const withHole = (): string[] => {
  const list = new Array<string>(2);
  list[0] = POPPY_ISSUER;
  return list;
};

const thrownBy = (fn: () => unknown): unknown => {
  try {
    fn();
  } catch (error) {
    return error;
  }
};

describe('the poppy option', () => {
  test('gives access to the poppy sub-client', () => {
    const serverClient = new ServerClient({ ...baseOptions(), poppy: poppyOptions() });

    expect(serverClient.poppy).toBeInstanceOf(ServerPoppyClient);
    expect(serverClient.poppy).toBe(serverClient.poppy);
  });

  test('throws InvalidConfigurationError when reading poppy without the option', () => {
    const serverClient = new ServerClient(baseOptions());

    expect(() => serverClient.poppy).toThrowError(InvalidConfigurationError);
    expect(() => serverClient.poppy).toThrowError(
      'poppy is only available when the `poppy` option is configured on the ServerClient.'
    );
  });

  test('does not stop a domain resolver when the option is not set', () => {
    expect(() => new ServerClient({ ...baseOptions(), domain: async () => POPPY_DOMAIN })).not.toThrow();
  });

  // The issuer must equal `https://` plus the normalized domain, whatever way the domain was written.
  test.each(['auth.zepto.example', 'https://auth.zepto.example', 'AUTH.zepto.example'])(
    'accepts the domain %s for the issuer of the config',
    (domain) => {
      const serverClient = new ServerClient({ ...baseOptions(), domain, poppy: poppyOptions() });

      expect(serverClient.poppy).toBeInstanceOf(ServerPoppyClient);
    }
  );

  test.each([{}, { resource: 'https://shop.zepto.example' }, { authorization_servers: [] }])(
    'accepts the protectedResource %j',
    (protectedResource) => {
      const serverClient = new ServerClient({
        ...baseOptions(),
        poppy: poppyOptions({ poppy: { protectedResource } }),
      });

      expect(serverClient.poppy).toBeInstanceOf(ServerPoppyClient);
    }
  );

  type Refusal = {
    name: string;
    /** The field that the message names first. */
    field: string;
    /** The `domain` option. Default: a static domain that matches the config. */
    domain?: ServerClientOptions['domain'];
    /** Replaces members of the valid config. */
    config?: Record<string, unknown>;
    /** Replaces members of the `poppy` option. */
    poppy?: Record<string, unknown>;
    /** The refused value, when it is a string. The message must not repeat it. */
    value?: string;
  };

  const refusals: Refusal[] = [
    { name: 'a domain resolver', field: 'domain', domain: async () => POPPY_DOMAIN },

    { name: 'a missing config', field: 'config', poppy: { config: undefined } },
    { name: 'a config that is an array', field: 'config', poppy: { config: [] } },
    {
      name: 'the config as a JSON string',
      field: 'config',
      poppy: { config: '{"issuer":"x"}' },
      value: '{"issuer":"x"}',
    },

    {
      name: 'protocol_version v0.3',
      field: 'config.protocol_version',
      config: { protocol_version: 'v0.3' },
      value: 'v0.3',
    },
    { name: 'protocol_version as a number', field: 'config.protocol_version', config: { protocol_version: 0.3 } },

    { name: 'a missing organization', field: 'config.organization.name', config: { organization: undefined } },
    {
      name: 'an empty organization.name',
      field: 'config.organization.name',
      config: { organization: { name: '', domain: 'zepto.example' } },
    },
    ...(
      [
        ['with a scheme', 'https://zepto.example'],
        ['with a port', 'zepto.example:8443'],
        ['with a path', 'zepto.example/shop'],
        ['in capitals', 'Zepto.example'],
        ['with a final dot', 'zepto.example.'],
      ] as const
    ).map(([what, domain]) => ({
      name: `organization.domain ${what}`,
      field: 'config.organization.domain',
      config: { organization: { name: 'Zepto', domain } },
      value: domain,
    })),
    {
      name: 'organization.domain as a list',
      field: 'config.organization.domain',
      config: { organization: { name: 'Zepto', domain: ['zepto.example'] } },
    },

    ...['https://auth.zepto.example', 'https://AUTH.zepto.example/', 'https://evil.example/'].map((issuer) => ({
      name: `issuer ${issuer}`,
      field: 'config.issuer',
      config: { issuer },
      value: issuer,
    })),

    { name: 'a missing web section', field: 'config.web.browser_session_endpoint', config: { web: undefined } },
    ...(
      [
        ['over http', 'http://auth.zepto.example/poppy/web_app_client/browser-session'],
        ['not a url', 'not a url'],
      ] as const
    ).map(([what, browser_session_endpoint]) => ({
      name: `browser_session_endpoint ${what}`,
      field: 'config.web.browser_session_endpoint',
      config: { web: { client_id: POPPY_CLIENT_ID, browser_session_endpoint } },
      value: browser_session_endpoint,
    })),
    {
      name: 'web.client_id of another client',
      field: 'config.web.client_id',
      config: { web: { ...createPoppyConfig().web, client_id: 'other_client' } },
      value: 'other_client',
    },
    ...(
      [
        ['a string', 'true'],
        ['a number', 1],
        ['null', null],
        ['an object', { value: true }],
      ] as const
    ).map(([what, unscoped]) => ({
      name: `web.unscoped as ${what}`,
      field: 'config.web.unscoped',
      config: { web: { ...createPoppyConfig().web, unscoped } },
    })),

    { name: 'scopes as an array', field: 'config.scopes', config: { scopes: [] } },
    {
      name: 'a scope name with a space',
      field: 'config.scopes',
      config: { scopes: { 'bad scope': { description: 'Bad.' } } },
      value: 'bad scope',
    },
    {
      name: 'a scope that is a string',
      field: 'config.scopes',
      config: { scopes: { 'orders:read': 'See your orders.' } },
      value: 'See your orders.',
    },
    {
      name: 'an empty scope description',
      field: 'config.scopes',
      config: { scopes: { 'orders:read': { description: '' } } },
    },
    {
      name: 'hints that are not an object',
      field: 'config.scopes',
      config: { scopes: { 'orders:read': { description: 'See your orders.', hints: true } } },
    },
    {
      name: 'hints.changes maybe',
      field: 'config.scopes',
      config: {
        scopes: {
          'orders:read': { description: 'See your orders.', hints: { changes: 'maybe', personal_data: true } },
        },
      },
      value: 'maybe',
    },
    {
      name: 'hints.personal_data as a string',
      field: 'config.scopes',
      config: {
        scopes: {
          'orders:read': { description: 'See your orders.', hints: { changes: 'none', personal_data: 'yes' } },
        },
      },
      value: 'yes',
    },

    { name: 'apis as an object', field: 'config.apis', config: { apis: {} } },
    {
      name: 'an api that is a string',
      field: 'config.apis',
      config: { apis: ['https://zepto.example/api/openapi.json'] },
      value: 'https://zepto.example/api/openapi.json',
    },
    {
      name: 'an http api url',
      field: 'config.apis',
      config: { apis: [{ ...validApi, url: 'http://zepto.example/api/openapi.json' }] },
      value: 'http://zepto.example/api/openapi.json',
    },
    {
      name: 'an api without a description',
      field: 'config.apis',
      config: { apis: [{ type: 'openapi', url: validApi.url }] },
    },
    {
      name: 'an api without a type',
      field: 'config.apis',
      config: { apis: [{ url: validApi.url, description: validApi.description }] },
    },

    { name: 'agentSessionMaxAge 0', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: 0 } },
    { name: 'agentSessionMaxAge -1', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: -1 } },
    { name: 'agentSessionMaxAge 1.5', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: 1.5 } },
    {
      name: 'agentSessionMaxAge as a string',
      field: 'agentSessionMaxAge',
      poppy: { agentSessionMaxAge: '7200' },
      value: '7200',
    },
    { name: 'agentSessionMaxAge NaN', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: NaN } },
    { name: 'agentSessionMaxAge Infinity', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: Infinity } },
    {
      name: 'agentSessionMaxAge 2 ** 53',
      field: 'agentSessionMaxAge',
      poppy: { agentSessionMaxAge: Number.MAX_SAFE_INTEGER + 1 },
    },

    { name: 'protectedResource as an array', field: 'protectedResource', poppy: { protectedResource: [] } },
    { name: 'protectedResource as null', field: 'protectedResource', poppy: { protectedResource: null } },
    {
      name: 'protectedResource as a string',
      field: 'protectedResource',
      poppy: { protectedResource: 'x' },
      value: 'x',
    },
    {
      name: 'an empty protectedResource.resource',
      field: 'protectedResource.resource',
      poppy: { protectedResource: { resource: '' } },
    },
    {
      name: 'protectedResource.resource as a number',
      field: 'protectedResource.resource',
      poppy: { protectedResource: { resource: 1 } },
    },
    {
      name: 'authorization_servers as a string',
      field: 'protectedResource.authorization_servers',
      poppy: { protectedResource: { authorization_servers: POPPY_ISSUER } },
      value: POPPY_ISSUER,
    },
    {
      name: 'an empty authorization server',
      field: 'protectedResource.authorization_servers',
      poppy: { protectedResource: { authorization_servers: [''] } },
    },
    {
      name: 'authorization_servers with a number',
      field: 'protectedResource.authorization_servers',
      poppy: { protectedResource: { authorization_servers: [1] } },
    },
    {
      name: 'authorization_servers that is all holes',
      field: 'protectedResource.authorization_servers',
      poppy: { protectedResource: { authorization_servers: new Array(1) } },
    },
    {
      name: 'authorization_servers with a hole',
      field: 'protectedResource.authorization_servers',
      poppy: { protectedResource: { authorization_servers: withHole() } },
    },
  ];

  test.each(refusals)('refuses $name', ({ field, domain, config, poppy, value }) => {
    const error = thrownBy(
      () =>
        new ServerClient({ ...baseOptions(), domain: domain ?? POPPY_DOMAIN, poppy: poppyOptions({ config, poppy }) })
    );

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    const message = (error as Error).message;
    expect(message.startsWith(`${PREFIX}${field} `), message).toBe(true);
    if (value !== undefined) {
      expect(message).not.toContain(value);
    }
  });

  test('tells the developer that the issuer must match exactly, trailing slash included', () => {
    const poppy = poppyOptions({ config: { issuer: 'https://auth.zepto.example' } });
    const error = thrownBy(() => new ServerClient({ ...baseOptions(), poppy }));

    expect((error as Error).message).toContain('exactly');
    expect((error as Error).message).toContain('trailing slash');
  });

  // When a config has two faults, the message is about the rule that comes first. `field` is that rule.
  const twoFaults: Refusal[] = [
    {
      name: 'the domain before the protocol version',
      field: 'domain',
      domain: async () => POPPY_DOMAIN,
      config: { protocol_version: 'v0.4' },
    },
    {
      name: 'the protocol version before the issuer',
      field: 'config.protocol_version',
      config: { protocol_version: 'v0.4', issuer: 'https://evil.example/' },
    },
    {
      name: 'the issuer before the browser session endpoint',
      field: 'config.issuer',
      config: { issuer: 'https://evil.example/', web: { browser_session_endpoint: 'http://auth.zepto.example/' } },
    },
    {
      name: 'the apis before agentSessionMaxAge',
      field: 'config.apis',
      config: { apis: {} },
      poppy: { agentSessionMaxAge: 0 },
    },
    {
      name: 'agentSessionMaxAge before protectedResource',
      field: 'agentSessionMaxAge',
      poppy: { agentSessionMaxAge: 0, protectedResource: [] },
    },
  ];

  test.each(twoFaults)('reports $name', ({ field, domain, config, poppy }) => {
    const error = thrownBy(
      () =>
        new ServerClient({ ...baseOptions(), domain: domain ?? POPPY_DOMAIN, poppy: poppyOptions({ config, poppy }) })
    );

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    const message = (error as Error).message;
    expect(message.startsWith(`${PREFIX}${field} `), message).toBe(true);
  });
});

// Only the shape of the version is checked: `major.minor`. The package does not know which versions exist, so it does
// not refuse a version it has not seen, and it serves the version as the config writes it (see discovery.spec.ts).
describe('the protocol_version of the config', () => {
  const client = { domain: POPPY_DOMAIN, clientId: POPPY_CLIENT_ID };
  // One text for every refused value. It holds no part of the value.
  const MESSAGE = `${PREFIX}config.protocol_version must be a version such as '0.3'.`;

  const build = (protocol_version: unknown) =>
    new ServerClient({ ...baseOptions(), poppy: poppyOptions({ config: { protocol_version } }) });

  test.each(['0.3', '0.4', '1.0', '0.10', '10.20', '9999.9999'])('accepts the version %s', (version) => {
    expect(build(version).poppy).toBeInstanceOf(ServerPoppyClient);
  });

  test.each(['0.3', '0.4', '1.0', '0.10'])('keeps the version %s exactly as the config writes it', (version) => {
    const config = { ...createPoppyConfig(), protocol_version: version };
    const resolved = resolvePoppyOptions({ config, guestStore: stubStore() }, client);

    expect(resolved.config.protocol_version).toBe(version);
  });

  // `RegExp.test` turns some of these into text that matches, such as the number 0.3 and the list ['0.3'], so the type
  // has to be checked first.
  const refused: [string, unknown][] = [
    ['a missing version', undefined],
    ['null', null],
    ['a number', 0.3],
    ['the number 1', 1],
    ['true', true],
    ['an empty string', ''],
    ['a major number alone', '0'],
    ['a minor number alone', '.3'],
    ['a dot with no minor number', '0.'],
    ['a v in front', 'v0.3'],
    ['three parts', '0.3.1'],
    ['a suffix', '0.3-draft'],
    ['a comma', '0,3'],
    ['a space in front', ' 0.3'],
    ['a space at the end', '0.3 '],
    ['a line break at the end', '0.3\n'],
    ['too many digits in the major number', '12345.3'],
    ['too many digits in the minor number', '0.12345'],
    // The Arabic-Indic digits zero and three. Only the digits 0 to 9 count.
    ['digits of another script', '\u0660.\u0663'],
    ['a list of one version', ['0.3']],
    ['an empty object', {}],
    ['an object with the parts', { major: 0, minor: 3 }],
    ['a String object', new String('0.3')],
  ];

  test.each(refused)('refuses %s with a fixed message', (_name, version) => {
    const error = thrownBy(() => build(version));

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as Error).message).toBe(MESSAGE);
  });

  test('refuses a version in resolvePoppyOptions as well', () => {
    const config = { ...createPoppyConfig(), protocol_version: 'v0.3' };

    expect(thrownBy(() => resolvePoppyOptions({ config, guestStore: stubStore() }, client))).toMatchObject({
      name: 'InvalidConfigurationError',
      message: MESSAGE,
    });
  });
});

describe('resolvePoppyOptions', () => {
  const client = { domain: POPPY_DOMAIN, clientId: POPPY_CLIENT_ID };

  test('defaults agentSessionMaxAge to two hours', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore() };

    expect(resolvePoppyOptions(options, client).agentSessionMaxAge).toBe(7200);
    expect(resolvePoppyOptions({ ...options, agentSessionMaxAge: undefined }, client).agentSessionMaxAge).toBe(7200);
  });

  test('keeps agentSessionMaxAge when it is set', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore(), agentSessionMaxAge: 600 };

    expect(resolvePoppyOptions(options, client).agentSessionMaxAge).toBe(600);
  });

  test('returns a copy of the config, and the guest store it was given', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore() };
    const resolved = resolvePoppyOptions(options, client);

    expect(resolved.config).not.toBe(options.config);
    expect(resolved.config).toStrictEqual(options.config);
    // The guest store is the app's own object, with its own state, so it is not copied.
    expect(resolved.guestStore).toBe(options.guestStore);
  });

  // The caller keeps its own config. Each change below is made after the construction.
  type CallerConfig = ReturnType<typeof createPoppyConfig>;

  const laterConfigChanges: [string, (config: CallerConfig) => void][] = [
    ['replacing the issuer', (config) => (config.issuer = 'https://evil.example/')],
    ['replacing the domain of the organization', (config) => (config.organization.domain = 'evil.example')],
    [
      'replacing the endpoint of the browser session',
      (config) => (config.web.browser_session_endpoint = 'https://evil.example/join'),
    ],
    ['changing the description of a scope', (config) => (config.scopes!['orders:read']!.description = 'Changed.')],
    ['adding a scope', (config) => (config.scopes!['admin:all'] = { description: 'Everything.' })],
    ['removing the apis', (config) => (config.apis!.length = 0)],
  ];

  test.each(laterConfigChanges)('copies the config, so %s later does not reach it', (_change, change) => {
    const config = createPoppyConfig();
    const resolved = resolvePoppyOptions({ config, guestStore: stubStore() }, client);

    change(config);

    expect(resolved.config).not.toBe(config);
    expect(resolved.config).toStrictEqual(createPoppyConfig());
  });

  test('checks the copy it keeps, so a config member that changes between reads cannot get past the checks', () => {
    let reads = 0;
    const config = {
      ...createPoppyConfig(),
      get issuer() {
        reads += 1;
        return reads === 1 ? POPPY_ISSUER : 'https://evil.example/';
      },
    };
    const resolved = resolvePoppyOptions({ config, guestStore: stubStore() }, client);

    // The issuer that passed the check is the one that is kept, however often it is read.
    expect(resolved.config.issuer).toBe(POPPY_ISSUER);
    expect(resolved.config.issuer).toBe(POPPY_ISSUER);
  });

  // `structuredClone` throws a `DataCloneError` for these values. The error of this package is thrown instead, and its
  // text is fixed: it holds nothing of the value, the member or the error that the value raised.
  describe('a value that cannot be copied', () => {
    const cases = [
      {
        name: 'a function in the config',
        poppy: () => poppyOptions({ config: { extra: () => 1 } }),
        message: `${PREFIX}config must be plain JSON data.`,
      },
      {
        name: 'a function deep in the config',
        poppy: () => poppyOptions({ config: { extra: { list: [{ hidden: () => 1 }] } } }),
        message: `${PREFIX}config must be plain JSON data.`,
      },
      {
        name: 'a symbol in the config',
        poppy: () => poppyOptions({ config: { extra: Symbol('secret-symbol') } }),
        message: `${PREFIX}config must be plain JSON data.`,
      },
      {
        name: 'a config member whose getter throws',
        // Built by hand: the helper spreads its config, which would call the getter before the SDK sees the object.
        poppy: () =>
          ({
            config: {
              ...createPoppyConfig(),
              get extra(): never {
                throw new Error('secret-getter-text');
              },
            },
            guestStore: stubStore(),
          }) as PoppyOptions,
        message: `${PREFIX}config must be plain JSON data.`,
      },
      {
        name: 'a function in the protectedResource',
        poppy: () => poppyOptions({ poppy: { protectedResource: { extension: () => 1 } } }),
        message: `${PREFIX}protectedResource must be plain JSON data.`,
      },
      {
        name: 'a function deep in the protectedResource',
        poppy: () => poppyOptions({ poppy: { protectedResource: { extension: { list: [{ hidden: () => 1 }] } } } }),
        message: `${PREFIX}protectedResource must be plain JSON data.`,
      },
    ];

    test.each(cases)('is refused with a fixed message: $name', ({ poppy, message }) => {
      const error = thrownBy(() => new ServerClient({ ...baseOptions(), poppy: poppy() }));

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as Error).message).toBe(message);
    });

    test.each(cases)('is refused by resolvePoppyOptions as well: $name', ({ poppy, message }) => {
      const error = thrownBy(() => resolvePoppyOptions(poppy(), client));

      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as Error).message).toBe(message);
    });
  });

  test('leaves protectedResource out when the option is not set', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore() };

    expect(resolvePoppyOptions(options, client).protectedResource).toBeUndefined();
  });

  test('keeps the members of protectedResource as they are, and adds none', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore() };

    expect(resolvePoppyOptions({ ...options, protectedResource: {} }, client).protectedResource).toStrictEqual({});
    expect(
      resolvePoppyOptions({ ...options, protectedResource: { scopes_supported: ['orders:read'] } }, client)
        .protectedResource
    ).toStrictEqual({ scopes_supported: ['orders:read'] });
  });

  // The caller keeps its own object. Each change below is made after the construction.
  const makeProtectedResource = () => ({
    resource: 'https://shop.zepto.example',
    authorization_servers: [POPPY_ISSUER],
    scopes_supported: ['orders:read'],
    extension: { limits: { orders: 10 }, regions: ['eu'] },
  });
  type CallerResource = ReturnType<typeof makeProtectedResource>;

  const laterChanges: [string, (resource: CallerResource) => void][] = [
    ['replacing a member', (resource) => (resource.resource = 'https://evil.example')],
    ['pushing to authorization_servers', (resource) => resource.authorization_servers.push('https://evil.example/')],
    ['pushing to scopes_supported', (resource) => resource.scopes_supported.push('checkout')],
    ['replacing a member of a nested object', (resource) => (resource.extension.limits = { orders: 1000 })],
    ['changing a value in a nested object', (resource) => (resource.extension.limits.orders = 1000)],
    ['changing an element of a nested array', (resource) => (resource.extension.regions[0] = 'us')],
  ];

  test.each(laterChanges)('copies protectedResource, so %s later does not reach it', (_change, change) => {
    const protectedResource = makeProtectedResource();
    const resolved = resolvePoppyOptions(
      { config: createPoppyConfig(), guestStore: stubStore(), protectedResource },
      client
    );

    change(protectedResource);

    expect(resolved.protectedResource).not.toBe(protectedResource);
    expect(resolved.protectedResource).toStrictEqual(makeProtectedResource());
  });

  test('checks the copy it keeps, so a member that changes between reads cannot get past the checks', () => {
    let reads = 0;
    const protectedResource: Record<string, unknown> = {
      get resource() {
        reads += 1;
        return reads === 1 ? 'https://shop.zepto.example' : 5;
      },
    };
    const resolved = resolvePoppyOptions(
      { config: createPoppyConfig(), guestStore: stubStore(), protectedResource },
      client
    );

    expect(resolved.protectedResource).toStrictEqual({ resource: 'https://shop.zepto.example' });
  });

  test('keeps a __proto__ member of parsed JSON as plain data, and does not change the prototype of the copy', () => {
    const protectedResource = JSON.parse('{"resource":"https://shop.zepto.example","__proto__":{"polluted":true}}');
    const resolved = resolvePoppyOptions(
      { config: createPoppyConfig(), guestStore: stubStore(), protectedResource },
      client
    );
    const copy = resolved.protectedResource!;

    expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
    expect(Object.keys(copy)).toStrictEqual(['resource', '__proto__']);
    expect(Object.getOwnPropertyDescriptor(copy, '__proto__')?.value).toStrictEqual({ polluted: true });
    expect(copy.polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  test('refuses a client without a static domain', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore() };

    expect(() => resolvePoppyOptions(options, { domain: undefined, clientId: POPPY_CLIENT_ID })).toThrowError(
      `${PREFIX}domain must be a string.`
    );
  });
});

describe('UserClaims', () => {
  test('types the Poppy members of the act claim', () => {
    type Act = NonNullable<UserClaims['act']>;

    expectTypeOf<Act['sub']>().toEqualTypeOf<string>();
    expectTypeOf<Act['poppy_sid']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<Act['poppy_user_id']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<Act['poppy_agent_id']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<Act['poppy_session_exp']>().toEqualTypeOf<number | undefined>();
  });
});
