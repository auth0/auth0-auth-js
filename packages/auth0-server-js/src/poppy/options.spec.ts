import { describe, expect, expectTypeOf, test, vi } from 'vitest';
import { InvalidConfigurationError } from '../errors.js';
import { ServerClient } from '../server-client.js';
import type { ServerClientOptions, UserClaims } from '../types.js';
import {
  POPPY_CLIENT_ID,
  POPPY_DOMAIN,
  POPPY_ISSUER,
  createPoppyConfig,
  createPoppyFile,
} from '../test-utils/poppy.js';
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

  // Poppy 1.0, section 3.1: the domain is the host that serves the document, with its port when it is not 443.
  test.each(['zepto.example:8443', 'localhost:3000', 'zepto.example:1', 'zepto.example:65535', 'localhost'])(
    'accepts the organization.domain %s, and names the protected resource with it',
    (domain) => {
      const config = { organization: { name: 'Zepto', domain } };
      const serverClient = new ServerClient({ ...baseOptions(), poppy: poppyOptions({ config }) });
      const resource = serverClient.poppy.getDiscoveryDocument('/.well-known/oauth-protected-resource');
      const poppyJson = serverClient.poppy.getDiscoveryDocument('/.well-known/poppy.json');

      expect(JSON.parse(resource?.body ?? '{}')).toMatchObject({ resource: `https://${domain}` });
      expect(JSON.parse(poppyJson?.body ?? '{}')).toMatchObject({ organization: { name: 'Zepto', domain } });
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

    { name: 'a missing organization', field: 'config.organization.domain', config: { organization: undefined } },
    {
      name: 'an organization that is a string',
      field: 'config.organization.domain',
      config: { organization: 'zepto.example' },
      value: 'zepto.example',
    },
    { name: 'a missing organization.domain', field: 'config.organization.domain', config: { organization: {} } },
    ...(
      [
        ['with a scheme', 'https://zepto.example'],
        ['with the port 443, which is left out', 'zepto.example:443'],
        ['with a port that is not a number', 'zepto.example:https'],
        ['with an empty port', 'zepto.example:'],
        ['with a port that starts with 0', 'zepto.example:08443'],
        ['with a port above 65535', 'zepto.example:65536'],
        ['with the port 0', 'zepto.example:0'],
        ['with two ports', 'zepto.example:8443:8443'],
        ['with a port and a path', 'zepto.example:8443/shop'],
        ['with a port and a scheme', 'https://zepto.example:8443'],
        ['with a path', 'zepto.example/shop'],
        ['in capitals', 'Zepto.example'],
        ['with a final dot', 'zepto.example.'],
        ['empty', ''],
      ] as const
    ).map(([what, domain]) => ({
      name: `organization.domain ${what}`,
      field: 'config.organization.domain',
      config: { organization: { name: 'Zepto', domain } },
      value: domain === '' ? undefined : domain,
    })),
    ...(
      [
        ['a list', ['zepto.example']],
        ['a number', 8443],
        ['null', null],
      ] as const
    ).map(([what, domain]) => ({
      name: `organization.domain as ${what}`,
      field: 'config.organization.domain',
      config: { organization: { name: 'Zepto', domain } },
    })),

    ...['https://auth.zepto.example', 'https://AUTH.zepto.example/', 'https://evil.example/'].map((issuer) => ({
      name: `issuer ${issuer}`,
      field: 'config.auth.issuer',
      config: { auth: { issuer } },
      value: issuer,
    })),
    { name: 'a missing auth', field: 'config.auth.issuer', config: { auth: undefined } },
    { name: 'auth as a string', field: 'config.auth.issuer', config: { auth: POPPY_ISSUER }, value: POPPY_ISSUER },
    { name: 'a missing auth.issuer', field: 'config.auth.issuer', config: { auth: { scopes: {} } } },
    { name: 'auth.issuer as a list', field: 'config.auth.issuer', config: { auth: { issuer: [POPPY_ISSUER] } } },
    {
      // The issuer used to be a member of the file itself. It is read from `auth` now.
      name: 'the issuer outside auth',
      field: 'config.auth.issuer',
      config: { auth: undefined, issuer: POPPY_ISSUER },
      value: POPPY_ISSUER,
    },

    { name: 'agentSessionMaxAge 0', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: 0 } },
    // A session ends 30 seconds before its deadline, so a value of 30 or less would refuse every agent login.
    { name: 'agentSessionMaxAge 10', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: 10 } },
    { name: 'agentSessionMaxAge 30', field: 'agentSessionMaxAge', poppy: { agentSessionMaxAge: 30 } },
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

    // The guard reads the guest store on every login. A missing one would fail on a visitor's login, after the code is spent.
    { name: 'a missing guestStore', field: 'guestStore', poppy: { guestStore: undefined } },
    { name: 'a guestStore that is null', field: 'guestStore', poppy: { guestStore: null } },
    { name: 'a guestStore that is an empty object', field: 'guestStore', poppy: { guestStore: {} } },
    {
      name: 'a guestStore without delete',
      field: 'guestStore',
      poppy: { guestStore: { get: async () => undefined, set: async () => undefined } },
    },
    { name: 'a guestStore that is a string', field: 'guestStore', poppy: { guestStore: 'store' }, value: 'store' },

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
      // The issuer message names the issuer that the `domain` of the app expects. That text is the app's, not the file's,
      // so it may equal a refused value, and it is taken out before the check.
      const shown = message.replace(`Expected: https://${typeof domain === 'string' ? domain : POPPY_DOMAIN}/`, '');
      expect(shown).not.toContain(value);
    }
  });

  test('tells the developer that the issuer must match exactly, trailing slash included', () => {
    const poppy = poppyOptions({ config: { auth: { issuer: 'https://auth.zepto.example' } } });
    const error = thrownBy(() => new ServerClient({ ...baseOptions(), poppy }));

    expect((error as Error).message).toContain('exactly');
    expect((error as Error).message).toContain('trailing slash');
  });

  // The expected issuer comes from the `domain` option of the app, so it is safe to show, and the refused value is not.
  test('names the issuer that the domain of the app expects, and not the one that the file has', () => {
    const poppy = poppyOptions({ config: { auth: { issuer: 'https://other.example/' } } });
    const message = (thrownBy(() => new ServerClient({ ...baseOptions(), poppy })) as Error).message;

    expect(message).toContain(`Expected: https://${POPPY_DOMAIN}/`);
    expect(message).not.toContain('other.example');
  });

  // The port 443 is the default port of https, so the host that serves the file has none, and neither has the domain.
  test.each(['zepto.example:443', 'localhost:443'])('tells the developer to leave the port out of %s', (domain) => {
    const poppy = poppyOptions({ config: { organization: { name: 'Zepto', domain } } });
    const error = thrownBy(() => new ServerClient({ ...baseOptions(), poppy }));

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as Error).message).toBe(
      `${PREFIX}config.organization.domain must not have the port 443. Leave the port out, because 443 is the default.`
    );
  });

  // The other faults of the domain have their own texts, and none of them holds the value.
  test.each([
    ['a scheme', 'https://zepto.example', 'must be a lowercase host name'],
    ['capitals', 'Zepto.example', 'must be a lowercase host name'],
    ['a port that is not a number', 'zepto.example:https', 'must be a lowercase host name'],
    ['a port that starts with 0', 'zepto.example:08443', 'must have a port from 1 to 65535'],
    ['the port 0', 'zepto.example:0', 'must have a port from 1 to 65535'],
    ['a port above 65535', 'zepto.example:65536', 'must have a port from 1 to 65535'],
  ])('tells the developer what is wrong with a domain with %s', (_what, domain, text) => {
    const poppy = poppyOptions({ config: { organization: { name: 'Zepto', domain } } });
    const error = thrownBy(() => new ServerClient({ ...baseOptions(), poppy }));

    expect((error as Error).message).toContain(`config.organization.domain ${text}`);
    expect((error as Error).message).not.toContain(domain);
  });

  // When a config has two faults, the message is about the rule that comes first. `field` is that rule.
  const twoFaults: Refusal[] = [
    {
      name: 'the domain resolver before the config',
      field: 'domain',
      domain: async () => POPPY_DOMAIN,
      config: { organization: undefined },
    },
    {
      name: 'the organization.domain before the issuer',
      field: 'config.organization.domain',
      config: { organization: { domain: 'Zepto.example' }, auth: { issuer: 'https://evil.example/' } },
    },
    {
      name: 'the issuer before agentSessionMaxAge',
      field: 'config.auth.issuer',
      config: { auth: { issuer: 'https://evil.example/' } },
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

// The config is the file that `auth0 poppy config` writes, and the Auth0 CLI is the one that makes it right. The
// package checks the two members that it reads to compare with a login and with the website, and nothing else.
describe('what is not checked in the config', () => {
  const client = { domain: POPPY_DOMAIN };

  const build = (config: Record<string, unknown>) =>
    new ServerClient({ ...baseOptions(), poppy: poppyOptions({ config }) });

  const file = createPoppyFile();

  test.each<[string, Record<string, unknown>]>([
    ['no protocol_version', { protocol_version: undefined }],
    ['protocol_version as a number', { protocol_version: 1 }],
    ['protocol_version v0.3', { protocol_version: 'v0.3' }],
    ['no organization.name', { organization: { domain: 'zepto.example' } }],
    ['an empty organization.name', { organization: { name: '', domain: 'zepto.example' } }],
    ['scopes as a list', { auth: { ...file.auth, scopes: ['orders:read'] } }],
    ['scopes with a name that has a space', { auth: { ...file.auth, scopes: { 'bad scope': 'Bad.' } } }],
    ['scopes that are objects', { auth: { ...file.auth, scopes: { 'orders:read': { description: 'See.' } } } }],
    ['scope_hints with unknown values', { auth: { ...file.auth, scope_hints: { a: { changes: 'maybe' } } } }],
    ['no auth.scopes', { auth: { issuer: POPPY_ISSUER } }],
    ['apis as an object', { apis: {} }],
    ['an api that is a string', { apis: ['https://zepto.example/openapi.json'] }],
    ['an http api url', { apis: [{ type: 'openapi', url: 'http://zepto.example/openapi.json', description: 'x' }] }],
    ['no web', { web: undefined }],
    ['a web.browser_session_endpoint over http', { web: { browser_session_endpoint: 'http://auth.zepto.example/' } }],
    ['web.client_id of another client', { web: { ...file.web, client_id: 'other_client' } }],
    ['web.unscoped as a string', { web: { ...file.web, unscoped: 'true' } }],
    ['members that the package does not know', { extra: 1, more: { list: [null] } }],
  ])('accepts a config with %s', (_what, config) => {
    expect(build(config).poppy).toBeInstanceOf(ServerPoppyClient);
  });

  test('accepts a config with only organization.domain and auth.issuer', () => {
    const config = { organization: { domain: 'zepto.example' }, auth: { issuer: POPPY_ISSUER } };

    expect(resolvePoppyOptions({ config, guestStore: stubStore() }, client).config).toStrictEqual(config);
  });

  test('keeps every member of the file, in its order, and keeps the members that it does not know', () => {
    const config = {
      web: { unscoped: true, browser_session_endpoint: 'https://auth.zepto.example/join', extra: 1 },
      future: { list: [1, 'two', null] },
      auth: { scopes: { b: 'b', a: 'a' }, issuer: POPPY_ISSUER, extra: true },
      organization: { domain: 'zepto.example', name: 'Zepto', extra: 'x' },
    };
    const resolved = resolvePoppyOptions({ config, guestStore: stubStore() }, client);

    expect(resolved.config).toStrictEqual(config);
    expect(Object.keys(resolved.config)).toStrictEqual(['web', 'future', 'auth', 'organization']);
    expect(Object.keys(resolved.config.auth)).toStrictEqual(['scopes', 'issuer', 'extra']);
  });
});

describe('resolvePoppyOptions', () => {
  const client = { domain: POPPY_DOMAIN };

  test('defaults agentSessionMaxAge to two hours', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore() };

    expect(resolvePoppyOptions(options, client).agentSessionMaxAge).toBe(7200);
    expect(resolvePoppyOptions({ ...options, agentSessionMaxAge: undefined }, client).agentSessionMaxAge).toBe(7200);
  });

  test('accepts the smallest agentSessionMaxAge that can work, which is one second above the leeway', () => {
    const options = { config: createPoppyConfig(), guestStore: stubStore(), agentSessionMaxAge: 31 };

    expect(resolvePoppyOptions(options, client).agentSessionMaxAge).toBe(31);
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
  type CallerConfig = ReturnType<typeof createPoppyFile>;

  const laterConfigChanges: [string, (config: CallerConfig) => void][] = [
    ['replacing the issuer', (config) => (config.auth.issuer = 'https://evil.example/')],
    ['replacing the domain of the organization', (config) => (config.organization.domain = 'evil.example')],
    ['replacing auth', (config) => (config.auth = { ...config.auth, issuer: 'https://evil.example/' })],
    ['replacing the protocol version', (config) => (config.protocol_version = '9.9')],
    [
      'replacing the endpoint of the browser session',
      (config) => (config.web.browser_session_endpoint = 'https://evil.example/join'),
    ],
    ['changing a scope', (config) => (config.auth.scopes['orders:read'] = 'Changed.')],
    ['adding a scope', (config) => Object.assign(config.auth.scopes, { 'admin:all': 'admin:all' })],
    ['changing a hint', (config) => (config.auth.scope_hints.checkout.changes = 'none')],
    ['removing the apis', (config) => (config.apis.length = 0)],
    ['adding a member', (config) => Object.assign(config, { added: true })],
  ];

  test.each(laterConfigChanges)('copies the config, so %s later does not reach it', (_change, change) => {
    const config = createPoppyFile();
    const resolved = resolvePoppyOptions({ config, guestStore: stubStore() }, client);

    change(config);

    expect(resolved.config).not.toBe(config);
    expect(resolved.config).toStrictEqual(createPoppyConfig());
  });

  test('checks the copy it keeps, so a config member that changes between reads cannot get past the checks', () => {
    let reads = 0;
    const config = {
      ...createPoppyConfig(),
      get auth() {
        reads += 1;
        return { issuer: reads === 1 ? POPPY_ISSUER : 'https://evil.example/' };
      },
    };
    const resolved = resolvePoppyOptions({ config, guestStore: stubStore() }, client);

    // The issuer that passed the check is the one that is kept, however often it is read.
    expect(resolved.config.auth.issuer).toBe(POPPY_ISSUER);
    expect(resolved.config.auth.issuer).toBe(POPPY_ISSUER);
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

    expect(() => resolvePoppyOptions(options, { domain: undefined })).toThrowError(`${PREFIX}domain must be a string.`);
  });
});

describe('the identifiers of the other stores | the guest cookie', () => {
  // The guest cookie is named after the guest identifier (`__a0_poppy`, or `__Host-a0_poppy` with the defaults), and that
  // name is also the salt of its encryption. The cookie-backed stores find their cookies by the start of the name.
  const create = (options: Partial<ServerClientOptions>, poppy = true) =>
    new ServerClient({ ...baseOptions(), ...(poppy && { poppy: poppyOptions() }), ...options });

  const anonymousStore = () => ({ ...stubStore(), deleteByLogoutToken: vi.fn() });

  test.each([
    { option: 'stateIdentifier', identifier: '__a0_poppy', why: 'is the guest identifier' },
    { option: 'stateIdentifier', identifier: '__a0_pop', why: 'is the start of the guest identifier' },
    { option: 'stateIdentifier', identifier: '__Host-a0_poppy', why: 'is the name of the guest cookie' },
    { option: 'stateIdentifier', identifier: '__Host-a0', why: 'is the start of the name of the guest cookie' },
    { option: 'transactionIdentifier', identifier: '__a0_poppy', why: 'is the guest identifier' },
    { option: 'transactionIdentifier', identifier: '__Host-', why: 'is the start of the name of the guest cookie' },
    { option: 'passkeyTransactionIdentifier', identifier: '__a0_poppy', why: 'is the guest identifier' },
    { option: 'passkeyTransactionIdentifier', identifier: '__a0_p', why: 'is the start of the guest identifier' },
    { option: 'stateIdentifier', identifier: '__a0_poppy.', why: 'is the start of a chunk of the guest cookie' },
    { option: 'stateIdentifier', identifier: '__a0_poppy.0', why: 'is the name of a chunk of the guest cookie' },
    {
      option: 'stateIdentifier',
      identifier: '__a0_poppy.1',
      why: 'is the start of the name of chunks of the guest cookie',
    },
    {
      option: 'transactionIdentifier',
      identifier: '__Host-a0_poppy.',
      why: 'is the start of a chunk of the guest cookie',
    },
  ] as const)('refuses $option $identifier, which $why', ({ option, identifier }) => {
    const error = thrownBy(() => create({ [option]: identifier }));

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as Error).message).toContain(PREFIX);
    expect((error as Error).message).toContain(`${option} ('${identifier}')`);
  });

  test('refuses anonymousSessionIdentifier when the anonymous store is configured', () => {
    const error = thrownBy(() =>
      create({ anonymousStore: anonymousStore(), anonymousSessionIdentifier: '__a0_poppy' })
    );

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as Error).message).toContain("anonymousSessionIdentifier ('__a0_poppy')");
  });

  test('leaves anonymousSessionIdentifier alone when there is no anonymous store: nothing reads it', () => {
    expect(() => create({ anonymousSessionIdentifier: '__a0_poppy' })).not.toThrow();
  });

  test.each(['__a0_poppy_extra', '__a0_poppyx', '__a0_session_poppy', 'my_session'])(
    'accepts stateIdentifier %s, which is not the guest identifier or the start of it',
    (stateIdentifier) => {
      expect(() => create({ stateIdentifier })).not.toThrow();
    }
  );

  test('accepts the default identifiers', () => {
    expect(() => create({ anonymousStore: anonymousStore() })).not.toThrow();
  });

  test('does not look at the identifiers without the poppy option', () => {
    expect(() => create({ stateIdentifier: '__a0_poppy' }, false)).not.toThrow();
  });
});

describe('UserClaims', () => {
  test('types the Poppy members of the act claim', () => {
    type Act = NonNullable<UserClaims['act']>;

    expectTypeOf<Act['sub']>().toEqualTypeOf<string>();
    expectTypeOf<Act['poppy_sid']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<Act['poppy_user_id']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<Act['poppy_agent_id']>().toEqualTypeOf<string | undefined>();
  });
});
