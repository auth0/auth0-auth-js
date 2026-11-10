import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, expectTypeOf, test } from 'vitest';
import { IssuerValidationError } from '../errors.js';
import * as sdk from '../index.js';
import type { PoppyConfigIssue, PoppyConfigIssueCode, PoppyDiscoveryDocument } from '../index.js';
import { ServerClient } from '../server-client.js';
import { CookieTransactionStore } from '../store/cookie-transaction-store.js';
import { StatelessStateStore } from '../store/stateless-state-store.js';
import {
  BrowserCookieHandler,
  POPPY_CLIENT_ID,
  POPPY_DOMAIN,
  POPPY_ISSUER,
  createPoppyConfig,
} from '../test-utils/poppy.js';
import type { Browser } from '../test-utils/poppy.js';
import { DISCOVERY_HEADERS, POPPY_JSON_PATH, PROTECTED_RESOURCE_PATH } from './constants.js';
import type { ServerPoppyClient } from './server-poppy-client.js';
import { StatelessPoppyGuestStore } from './stateless-poppy-guest-store.js';
import type { PoppyConfig, PoppyProtectedResource } from './types.js';

// These tests go through the public API. A fake Auth0 answers the discovery request that `verifyConfig()` sends with
// the metadata that a test sets. When a test sets none, the fake answers with a server error.

const SECRET = '<secret>';
const RESOURCE = 'https://zepto.example';

let metadata: Record<string, unknown> | undefined;

const server = setupServer(
  http.get(`https://${POPPY_DOMAIN}/.well-known/openid-configuration`, () =>
    metadata === undefined
      ? new HttpResponse(null, { status: 500 })
      : HttpResponse.json({
          issuer: POPPY_ISSUER,
          authorization_endpoint: `https://${POPPY_DOMAIN}/authorize`,
          token_endpoint: `https://${POPPY_DOMAIN}/oauth/token`,
          ...metadata,
        })
  )
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());

beforeEach(() => {
  metadata = undefined;
});

afterEach(() => {
  server.resetHandlers();
});

interface ClientOptions {
  /** Default: the Zepto config. */
  config?: PoppyConfig;
  protectedResource?: PoppyProtectedResource;
}

// The Poppy client of a website. Every client reads the metadata of Auth0 for itself, so a test sets `metadata` before
// it creates the client or asks.
function createClient(options: ClientOptions = {}): ServerPoppyClient<Browser> {
  const cookies = new BrowserCookieHandler();

  return new ServerClient<Browser>({
    domain: POPPY_DOMAIN,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    discoveryCache: { ttl: 0 },
    transactionStore: new CookieTransactionStore<Browser>({ secret: SECRET }, cookies),
    stateStore: new StatelessStateStore<Browser>({ secret: SECRET }, cookies),
    poppy: {
      config: options.config ?? createPoppyConfig(),
      guestStore: new StatelessPoppyGuestStore<Browser>({ secret: SECRET }, cookies),
      protectedResource: options.protectedResource,
    },
  }).poppy;
}

function documentOf(client: ServerPoppyClient<Browser>, path: string): PoppyDiscoveryDocument {
  const document = client.getDiscoveryDocument(path);
  expect(document).toBeDefined();

  return document!;
}

const bodyOf = (client: ServerPoppyClient<Browser>, path: string) => documentOf(client, path).body;

// The bodies for the Zepto config, character for character. The order of the keys is part of the contract.
const POPPY_JSON =
  '{"protocol_version":"0.3","organization":{"name":"Zepto","domain":"zepto.example"},"auth":{"issuer":"https://auth.zepto.example/","scopes":{"orders:read":"See your orders.","checkout":"Place orders and pay."},"scope_hints":{"orders:read":{"changes":"none","personal_data":true},"checkout":{"changes":"irreversible","personal_data":true}}},"web":{"browser_session_endpoint":"https://auth.zepto.example/poppy/web_app_client/browser-session"},"apis":[{"type":"openapi","url":"https://zepto.example/api/openapi.json","description":"Orders and checkout"}]}';
const INFERRED = '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"]}';

// The poppy.json of the Zepto config as an object, for a test to change and write out again. Changing a member keeps
// its place, so the order of the keys stays the one of the contract.
const zeptoPoppyJson = () => JSON.parse(POPPY_JSON);

describe('poppy.getDiscoveryDocument | the documents for the Zepto config', () => {
  test('poppy.json has exactly this body', () => {
    expect(bodyOf(createClient(), POPPY_JSON_PATH)).toBe(POPPY_JSON);
  });

  test('oauth-protected-resource has exactly this body', () => {
    expect(bodyOf(createClient(), PROTECTED_RESOURCE_PATH)).toBe(INFERRED);
  });

  test('both documents are JSON that can be cached for five minutes', () => {
    const client = createClient();

    for (const path of [POPPY_JSON_PATH, PROTECTED_RESOURCE_PATH]) {
      expect(documentOf(client, path).headers).toStrictEqual({
        'content-type': 'application/json',
        'cache-control': 'public, max-age=300',
      });
    }
  });
});

describe.each([
  [POPPY_JSON_PATH, POPPY_JSON],
  [PROTECTED_RESOURCE_PATH, INFERRED],
])('poppy.getDiscoveryDocument | %s', (path, body) => {
  test('is served with the status 200 and the discovery headers', () => {
    expect(createClient().getDiscoveryDocument(path)).toStrictEqual({
      status: 200,
      headers: { ...DISCOVERY_HEADERS },
      body,
    });
  });

  test('is a new object on every call, so a change by the app does not reach the next call', () => {
    const client = createClient();
    const first = documentOf(client, path);

    first.status = 500;
    first.headers['content-type'] = 'text/html';
    first.headers['set-cookie'] = 'a=b';
    delete first.headers['cache-control'];
    first.body = 'changed';

    const second = documentOf(client, path);

    expect(second).not.toBe(first);
    expect(second.headers).not.toBe(first.headers);
    expect(second).toStrictEqual({ status: 200, headers: { ...DISCOVERY_HEADERS }, body });
    // The constant that both documents take their headers from is untouched too.
    expect(DISCOVERY_HEADERS).toStrictEqual({
      'content-type': 'application/json',
      'cache-control': 'public, max-age=300',
    });
  });
});

describe('poppy.getDiscoveryDocument | other paths', () => {
  test.each([
    '/.well-known/other',
    '/.well-known/poppy.json?x=1',
    '/.well-known/oauth-protected-resource?x=1',
    '/.well-known/poppy.json#top',
    '/.well-known/poppy.json/',
    '/.well-known/POPPY.JSON',
    '.well-known/poppy.json',
    'https://zepto.example/.well-known/poppy.json',
    '',
    '/',
    '__proto__',
    'constructor',
  ])('gives undefined for the path %j', (path) => {
    expect(createClient().getDiscoveryDocument(path)).toBeUndefined();
  });
});

// The file says the version that its author wrote it for. The package does not know which versions exist, so it serves
// the value of the config as it is and never invents one.
describe('poppy.getDiscoveryDocument | the protocol_version of the config', () => {
  const withVersion = (protocol_version: string): PoppyConfig => ({ ...createPoppyConfig(), protocol_version });

  test.each(['0.3', '0.4', '1.0', '0.10', '2.5'])('poppy.json says the version %s of the config', (version) => {
    const expected = zeptoPoppyJson();
    expected.protocol_version = version;

    const body = bodyOf(createClient({ config: withVersion(version) }), POPPY_JSON_PATH);

    // Only the version differs from the Zepto file, and it keeps its place as the first member.
    expect(body).toBe(JSON.stringify(expected));
    expect(JSON.parse(body).protocol_version).toBe(version);
    expect(Object.keys(JSON.parse(body))[0]).toBe('protocol_version');
  });

  test('a config with 0.4 serves 0.4 and a config with 0.3 serves 0.3', () => {
    expect(bodyOf(createClient({ config: withVersion('0.4') }), POPPY_JSON_PATH)).toContain('"protocol_version":"0.4"');
    expect(bodyOf(createClient({ config: withVersion('0.3') }), POPPY_JSON_PATH)).toContain('"protocol_version":"0.3"');
  });

  test('oauth-protected-resource does not depend on the version', () => {
    expect(bodyOf(createClient({ config: withVersion('0.4') }), PROTECTED_RESOURCE_PATH)).toBe(INFERRED);
  });

  test('a later change of the version by the app does not reach the file', () => {
    const config = withVersion('0.4');
    const client = createClient({ config });
    const served = bodyOf(client, POPPY_JSON_PATH);

    config.protocol_version = '0.9';

    expect(served).toContain('"protocol_version":"0.4"');
    expect(bodyOf(client, POPPY_JSON_PATH)).toBe(served);
  });
});

// `web.unscoped` is a member of Poppy 0.4. It says that the website does not apply the other scopes, so an agent reads it
// before it asks for `poppy:browser-sign-in`. The file says what the config says.
describe('poppy.getDiscoveryDocument | web.unscoped', () => {
  const withUnscoped = (unscoped: boolean): PoppyConfig => {
    const config = createPoppyConfig();

    return { ...config, web: { ...config.web, unscoped } };
  };

  test.each([true, false])('poppy.json says unscoped %s after the browser_session_endpoint', (unscoped) => {
    const expected = zeptoPoppyJson();
    expected.web.unscoped = unscoped;

    const body = bodyOf(createClient({ config: withUnscoped(unscoped) }), POPPY_JSON_PATH);

    expect(body).toBe(JSON.stringify(expected));
    expect(Object.keys(JSON.parse(body).web)).toStrictEqual(['browser_session_endpoint', 'unscoped']);
  });

  test('poppy.json has no unscoped member when the config leaves it out', () => {
    expect(JSON.parse(bodyOf(createClient(), POPPY_JSON_PATH)).web).toStrictEqual({
      browser_session_endpoint: 'https://auth.zepto.example/poppy/web_app_client/browser-session',
    });
  });

  test('a later change of unscoped by the app does not reach the file', () => {
    const config = withUnscoped(true);
    const client = createClient({ config });
    const served = bodyOf(client, POPPY_JSON_PATH);

    config.web.unscoped = false;

    expect(bodyOf(client, POPPY_JSON_PATH)).toBe(served);
    expect(JSON.parse(served).web.unscoped).toBe(true);
  });
});

describe('poppy.getDiscoveryDocument | the protectedResource option', () => {
  const SECOND_SERVER =
    '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/","https://staff.zepto.example/"]}';
  const WITH_SCOPES =
    '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"],"scopes_supported":["orders:read"]}';

  const rows: Array<[string, PoppyProtectedResource | undefined, string]> = [
    ['none', undefined, INFERRED],
    ['an empty object', {}, INFERRED],
    ['members that are undefined', { resource: undefined, authorization_servers: undefined }, INFERRED],
    [
      'a second authorization server',
      { authorization_servers: [POPPY_ISSUER, 'https://staff.zepto.example/'] },
      SECOND_SERVER,
    ],
    [
      'a resource',
      { resource: 'https://shop.zepto.example' },
      '{"resource":"https://shop.zepto.example","authorization_servers":["https://auth.zepto.example/"]}',
    ],
    [
      'both members',
      { resource: 'https://shop.zepto.example', authorization_servers: ['https://staff.zepto.example/'] },
      '{"resource":"https://shop.zepto.example","authorization_servers":["https://staff.zepto.example/"]}',
    ],
    ['scopes_supported', { scopes_supported: ['orders:read'] }, WITH_SCOPES],
    [
      'scopes_supported written before the two members that always come first',
      { scopes_supported: ['orders:read'], authorization_servers: [POPPY_ISSUER], resource: RESOURCE },
      WITH_SCOPES,
    ],
    [
      'other members, in the order they were written',
      { service_documentation: 'https://zepto.example/docs', scopes_supported: ['orders:read'] },
      '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"],"service_documentation":"https://zepto.example/docs","scopes_supported":["orders:read"]}',
    ],
    [
      'the same other members, written the other way around',
      { scopes_supported: ['orders:read'], service_documentation: 'https://zepto.example/docs' },
      '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"],"scopes_supported":["orders:read"],"service_documentation":"https://zepto.example/docs"}',
    ],
    [
      'members of every JSON type',
      { a: 'text', b: 1.5, c: true, d: null, e: ['x', { y: [] }], f: { g: {} } },
      '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"],"a":"text","b":1.5,"c":true,"d":null,"e":["x",{"y":[]}],"f":{"g":{}}}',
    ],
    [
      'an empty authorization_servers',
      { authorization_servers: [] },
      '{"resource":"https://zepto.example","authorization_servers":[]}',
    ],
  ];

  test.each(rows)(
    'serves oauth-protected-resource for %s, and the same poppy.json',
    (_name, protectedResource, body) => {
      const client = createClient({ protectedResource });

      expect(bodyOf(client, PROTECTED_RESOURCE_PATH)).toBe(body);
      expect(bodyOf(client, POPPY_JSON_PATH)).toBe(POPPY_JSON);
    }
  );

  test('serves a __proto__ member of parsed JSON as data, and does not change the prototype of anything', () => {
    const protectedResource = JSON.parse('{"scopes_supported":["orders:read"],"__proto__":{"polluted":true}}');
    const body = bodyOf(createClient({ protectedResource }), PROTECTED_RESOURCE_PATH);

    expect(body).toBe(
      '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"],"scopes_supported":["orders:read"],"__proto__":{"polluted":true}}'
    );
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  // The caller keeps its own objects. Each change below is made after the construction.
  test('keeps what it serves, and what verifyConfig reports, when the app changes the objects it passed', async () => {
    const protectedResource = {
      resource: RESOURCE,
      authorization_servers: [POPPY_ISSUER, 'https://staff.zepto.example/'],
      scopes_supported: ['orders:read'],
    };
    const client = createClient({ protectedResource });
    const body = bodyOf(client, PROTECTED_RESOURCE_PATH);
    const issues = await client.verifyConfig();

    protectedResource.resource = 'https://evil.example';
    protectedResource.authorization_servers.length = 0;
    protectedResource.authorization_servers.push('https://evil.example/');
    protectedResource.scopes_supported.push('checkout');

    expect(body).toBe(
      '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/","https://staff.zepto.example/"],"scopes_supported":["orders:read"]}'
    );
    expect(bodyOf(client, PROTECTED_RESOURCE_PATH)).toBe(body);
    // The override was right when the client was made. A client that kept the object of the app would now report two
    // mismatches.
    expect(issues.map(({ code }) => code)).toStrictEqual(['metadata_unavailable']);
    expect(await client.verifyConfig()).toStrictEqual(issues);
  });

  test('keeps what it serves when the app changes the config afterwards', () => {
    const config = createPoppyConfig();
    const client = createClient({ config });

    config.organization.domain = 'evil.example';
    config.issuer = 'https://evil.example/';
    config.scopes!['orders:read']!.description = 'Changed.';
    config.web.browser_session_endpoint = 'https://evil.example/browser-session';
    config.apis!.length = 0;

    expect(bodyOf(client, POPPY_JSON_PATH)).toBe(POPPY_JSON);
    expect(bodyOf(client, PROTECTED_RESOURCE_PATH)).toBe(INFERRED);
  });

  // `parseLoginInitiation()` and `verifyConfig()` read the config when they are called, so they are asked after the
  // change.
  test('keeps what parseLoginInitiation accepts, and what verifyConfig reads, when the app changes the config', async () => {
    metadata = { scopes_supported: ['openid', 'orders:read', 'checkout'], protected_resources: [RESOURCE] };
    const config = createPoppyConfig();
    const client = createClient({ config });

    config.issuer = 'https://evil.example/';
    config.organization.domain = 'evil.example';
    config.scopes!['admin:all'] = { description: 'Everything.' };

    const loginWith = (iss: string) => new URL(`${RESOURCE}/login?iss=${encodeURIComponent(iss)}`);
    // The issuer of the config when the client was made is still the one that is accepted, and the new one is refused.
    expect(client.parseLoginInitiation(loginWith(POPPY_ISSUER), { appOrigin: RESOURCE })).toStrictEqual({
      authorizationParams: {},
    });
    expect(() => client.parseLoginInitiation(loginWith('https://evil.example/'), { appOrigin: RESOURCE })).toThrowError(
      IssuerValidationError
    );
    // The metadata lists the resource and the scopes of the config as it was. A client that read the changed object
    // would report the new resource and the new scope as missing.
    expect(await client.verifyConfig()).toStrictEqual([]);
  });
});

describe('poppy.getDiscoveryDocument | optional fields and members that are not served', () => {
  const poppyJsonOf = (config: PoppyConfig) => bodyOf(createClient({ config }), POPPY_JSON_PATH);

  test('no scopes: auth has the issuer and nothing else', () => {
    const config = createPoppyConfig();
    delete config.scopes;

    const expected = zeptoPoppyJson();
    expected.auth = { issuer: POPPY_ISSUER };

    expect(poppyJsonOf(config)).toBe(JSON.stringify(expected));
    expect(Object.keys(JSON.parse(poppyJsonOf(config)).auth)).toStrictEqual(['issuer']);
  });

  test('an empty scopes object is the same as no scopes', () => {
    const config = createPoppyConfig();
    config.scopes = {};

    const expected = zeptoPoppyJson();
    expected.auth = { issuer: POPPY_ISSUER };

    expect(poppyJsonOf(config)).toBe(JSON.stringify(expected));
  });

  test('a scope without hints is in scopes and not in scope_hints', () => {
    const config = createPoppyConfig();
    delete config.scopes!['orders:read']!.hints;

    const expected = zeptoPoppyJson();
    delete expected.auth.scope_hints['orders:read'];

    expect(poppyJsonOf(config)).toBe(JSON.stringify(expected));
    expect(Object.keys(expected.auth.scopes)).toStrictEqual(['orders:read', 'checkout']);
    expect(Object.keys(expected.auth.scope_hints)).toStrictEqual(['checkout']);
  });

  test('scopes without any hints leave scope_hints out', () => {
    const config = createPoppyConfig();
    delete config.scopes!['orders:read']!.hints;
    delete config.scopes!.checkout!.hints;

    const expected = zeptoPoppyJson();
    delete expected.auth.scope_hints;

    expect(poppyJsonOf(config)).toBe(JSON.stringify(expected));
    expect(poppyJsonOf(config)).not.toContain('scope_hints');
  });

  test.each([
    ['no apis', undefined],
    ['an empty apis list', []],
  ])('%s: there is no apis key', (_name, apis) => {
    const config = createPoppyConfig();
    config.apis = apis;

    const expected = zeptoPoppyJson();
    delete expected.apis;

    expect(poppyJsonOf(config)).toBe(JSON.stringify(expected));
    expect(poppyJsonOf(config)).not.toContain('apis');
  });

  test('the fields that only other tools read are not served', () => {
    const body = poppyJsonOf(createPoppyConfig());

    for (const text of ['agent.example', 'agents', 'identifier', 'public_origin', 'client_id']) {
      expect(body).not.toContain(text);
    }
  });

  // The file has more members than the ones this package reads, and the API SDK reads some of them. Only the members
  // that the document is built from are served, whatever else the file holds.
  test('a member that the document is not built from is not served, and the keys keep their order', () => {
    const config = createPoppyConfig();
    const addTo = (target: object, members: Record<string, unknown>) => Object.assign(target, members);

    addTo(config, { extra: 1, more: { extra: 1 } });
    addTo(config.organization, { extra: 'x' });
    addTo(config.web, { extra: 'x' });
    addTo(config.scopes!['orders:read']!, { extra: 'x' });
    addTo(config.apis![0]!, { extra: 'x' });
    // A hint written the other way around, with a member that is not a hint.
    addTo(config.scopes!.checkout!, { hints: { personal_data: true, changes: 'irreversible', extra: 'x' } });

    expect(poppyJsonOf(config)).toBe(POPPY_JSON);
  });

  test('serves a scope named __proto__ as a scope', () => {
    const config = createPoppyConfig();
    config.scopes = JSON.parse('{"__proto__":{"description":"Odd.","hints":{"changes":"none","personal_data":false}}}');

    const body = poppyJsonOf(config);

    expect(body).toContain('"scopes":{"__proto__":"Odd."}');
    expect(body).toContain('"scope_hints":{"__proto__":{"changes":"none","personal_data":false}}');
  });
});

describe('poppy.verifyConfig | the protectedResource option', () => {
  // These rows need no network. The request for the metadata fails (the fake answers 500), so `metadata_unavailable`
  // comes after the issues about the override.
  const codesOf = async (client: ServerPoppyClient<Browser>) => (await client.verifyConfig()).map(({ code }) => code);

  test.each<[string, PoppyProtectedResource | undefined]>([
    ['none', undefined],
    ['an empty object', {}],
    ['a second authorization server', { authorization_servers: [POPPY_ISSUER, 'https://staff.zepto.example/'] }],
    ['the issuer after another server', { authorization_servers: ['https://staff.zepto.example/', POPPY_ISSUER] }],
    ['the resource written out', { resource: RESOURCE, authorization_servers: [POPPY_ISSUER] }],
    ['other members', { scopes_supported: ['orders:read'], resource_name: 'Zepto' }],
  ])('reports no override issue for %s', async (_name, protectedResource) => {
    expect(await codesOf(createClient({ protectedResource }))).toStrictEqual(['metadata_unavailable']);
  });

  test.each<[string, PoppyProtectedResource, string]>([
    ['a resource on another host', { resource: 'https://shop.zepto.example' }, 'protectedResource.resource'],
    ['a resource with a trailing slash', { resource: 'https://zepto.example/' }, 'protectedResource.resource'],
    ['a resource in another case', { resource: 'https://ZEPTO.example' }, 'protectedResource.resource'],
    [
      'authorization_servers without the issuer',
      { authorization_servers: ['https://staff.zepto.example/'] },
      'protectedResource.authorization_servers',
    ],
    [
      'the issuer without its trailing slash',
      { authorization_servers: ['https://auth.zepto.example'] },
      'protectedResource.authorization_servers',
    ],
    [
      'the issuer in another case',
      { authorization_servers: ['https://AUTH.zepto.example/'] },
      'protectedResource.authorization_servers',
    ],
    ['an empty authorization_servers', { authorization_servers: [] }, 'protectedResource.authorization_servers'],
  ])(
    'reports one mismatch for %s, names the member and not the value, and still serves it',
    async (_name, protectedResource, member) => {
      const client = createClient({ protectedResource });
      const issues = await client.verifyConfig();

      expect(issues.map(({ code }) => code)).toStrictEqual([
        'protected_resource_override_mismatch',
        'metadata_unavailable',
      ]);
      expect(issues[0]!.message).toContain(member);
      expect(issues[0]!.message).not.toContain('staff.zepto.example');
      expect(issues[0]!.message).not.toContain('shop.zepto.example');
      // No value of the override is in the message, whatever the value is.
      const values = [protectedResource.resource, ...(protectedResource.authorization_servers ?? [])];
      for (const value of values.filter((value): value is string => typeof value === 'string')) {
        expect(issues[0]!.message).not.toContain(value);
      }
      // The developer wrote the value on purpose, so it is served as it is.
      expect(JSON.parse(bodyOf(client, PROTECTED_RESOURCE_PATH))).toMatchObject(protectedResource);
    }
  );

  test('reports a mismatch for each member that is wrong, the resource first', async () => {
    const client = createClient({
      protectedResource: {
        resource: 'https://shop.zepto.example',
        authorization_servers: ['https://staff.zepto.example/'],
      },
    });
    const issues = await client.verifyConfig();

    expect(issues.map(({ code }) => code)).toStrictEqual([
      'protected_resource_override_mismatch',
      'protected_resource_override_mismatch',
      'metadata_unavailable',
    ]);
    expect(issues[0]!.message).toContain('protectedResource.resource');
    expect(issues[1]!.message).toContain('protectedResource.authorization_servers');
  });
});

describe('poppy.verifyConfig | the metadata of Auth0', () => {
  const GOOD = { scopes_supported: ['openid', 'orders:read', 'checkout'], protected_resources: [RESOURCE] };

  const issuesFor = (served: Record<string, unknown> | undefined, options: ClientOptions = {}) => {
    metadata = served;

    return createClient(options).verifyConfig();
  };

  test('gives no issue when the metadata lists the resource and the scopes', async () => {
    expect(await issuesFor(GOOD)).toStrictEqual([]);
  });

  test('gives no issue for a resource in another case, or among other resources', async () => {
    expect(await issuesFor({ ...GOOD, protected_resources: ['https://ZEPTO.example'] })).toStrictEqual([]);
    expect(
      await issuesFor({
        ...GOOD,
        protected_resources: ['https://mcp.zepto.example/mcp', RESOURCE, 'https://zepto.example.co'],
      })
    ).toStrictEqual([]);
  });

  test('gives no issue for a valid override and good metadata', async () => {
    const protectedResource = { authorization_servers: [POPPY_ISSUER, 'https://staff.zepto.example/'] };

    expect(await issuesFor(GOOD, { protectedResource })).toStrictEqual([]);
  });

  test.each<[string, Record<string, unknown>]>([
    ['absent', { scopes_supported: GOOD.scopes_supported }],
    ['with a trailing slash', { ...GOOD, protected_resources: ['https://zepto.example/'] }],
    ['an empty list', { ...GOOD, protected_resources: [] }],
    ['a string and not a list', { ...GOOD, protected_resources: RESOURCE }],
    ['an object and not a list', { ...GOOD, protected_resources: { 0: RESOURCE } }],
    ['null', { ...GOOD, protected_resources: null }],
    ['another host', { ...GOOD, protected_resources: ['https://shop.zepto.example'] }],
    ['a longer host', { ...GOOD, protected_resources: ['https://zepto.example.evil.example'] }],
    ['with a port', { ...GOOD, protected_resources: ['https://zepto.example:443'] }],
    ['with a path', { ...GOOD, protected_resources: ['https://zepto.example/shop'] }],
    ['with another scheme', { ...GOOD, protected_resources: ['http://zepto.example'] }],
    ['entries that are not strings', { ...GOOD, protected_resources: [1, null, { href: RESOURCE }, [RESOURCE]] }],
  ])('gives one protected_resource_missing when protected_resources is %s', async (_name, served) => {
    const issues = await issuesFor(served);

    expect(issues).toHaveLength(1);
    expect(issues[0]!.code).toBe('protected_resource_missing');
    expect(issues[0]!.message).toContain(RESOURCE);
  });

  test('gives one scopes_not_supported that names the scopes that are missing', async () => {
    const issues = await issuesFor({ ...GOOD, scopes_supported: ['openid', 'orders:read'] });

    expect(issues).toHaveLength(1);
    expect(issues[0]!.code).toBe('scopes_not_supported');
    expect(issues[0]!.message).toContain('checkout');
    expect(issues[0]!.message).not.toContain('orders:read');
    expect(issues[0]!.message).not.toContain('openid');
  });

  // Poppy 0.4 defines `poppy:browser-sign-in`. A website that offers a browser join has to support it, so Auth0 should
  // list it, and a config of 0.4 or later is checked for it. The scopes of the config and the metadata here are for 0.4.
  describe('poppy:browser-sign-in', () => {
    const SIGN_IN = 'poppy:browser-sign-in';
    const configOf = (protocol_version: string): PoppyConfig => ({ ...createPoppyConfig(), protocol_version });
    const listing = (...scopes: string[]) => ({
      protected_resources: [RESOURCE],
      scopes_supported: ['openid', 'orders:read', 'checkout', ...scopes],
    });

    test.each(['0.4', '0.5', '0.10', '1.0', '2.7'])('names it for a config of %s when Auth0 does not list it', async (version) => {
      const issues = await issuesFor(listing(), { config: configOf(version) });

      expect(issues).toHaveLength(1);
      expect(issues[0]!.code).toBe('scopes_not_supported');
      expect(issues[0]!.message).toContain(SIGN_IN);
      // The scopes of the config are listed, so only the new scope is named.
      expect(issues[0]!.message).not.toContain('orders:read');
      expect(issues[0]!.message).not.toContain('checkout');
    });

    test.each(['0.4', '1.0'])('gives no issue for a config of %s when Auth0 lists it', async (version) => {
      expect(await issuesFor(listing(SIGN_IN), { config: configOf(version) })).toStrictEqual([]);
    });

    test.each(['0.3', '0.2', '0.0'])('does not look for it in a config of %s, where the scope does not exist', async (version) => {
      expect(await issuesFor(listing(), { config: configOf(version) })).toStrictEqual([]);
    });

    test('names it after the scopes of the config, in one issue', async () => {
      const issues = await issuesFor(
        { protected_resources: [RESOURCE], scopes_supported: ['openid'] },
        { config: configOf('0.4') }
      );

      expect(issues).toHaveLength(1);
      expect(issues[0]!.message).toContain(`scopes in scopes_supported: orders:read, checkout, ${SIGN_IN}.`);
    });

    test('names it once when the config lists it as a scope too', async () => {
      const config = configOf('0.4');
      config.scopes = { ...config.scopes, [SIGN_IN]: { description: 'Use the website signed in.' } };

      const issues = await issuesFor(listing(), { config });

      expect(issues).toHaveLength(1);
      expect(issues[0]!.message.split(SIGN_IN)).toHaveLength(2);
    });

    test('is checked for a config that has no scopes of its own', async () => {
      const config = configOf('0.4');
      config.scopes = undefined;

      const issues = await issuesFor({ protected_resources: [RESOURCE], scopes_supported: ['openid'] }, { config });

      expect(issues.map(({ code }) => code)).toStrictEqual(['scopes_not_supported']);
      expect(issues[0]!.message).toContain(SIGN_IN);
    });

    test.each<[string, Record<string, unknown>]>([
      ['absent', { protected_resources: [RESOURCE] }],
      ['a string and not a list', { protected_resources: [RESOURCE], scopes_supported: `openid ${SIGN_IN}` }],
      ['null', { protected_resources: [RESOURCE], scopes_supported: null }],
      ['in another case', { protected_resources: [RESOURCE], scopes_supported: ['Poppy:Browser-Sign-In'] }],
    ])('names it when scopes_supported is %s', async (_name, served) => {
      const config = configOf('0.4');
      config.scopes = undefined;

      const issues = await issuesFor(served, { config });

      expect(issues.map(({ code }) => code)).toStrictEqual(['scopes_not_supported']);
      expect(issues[0]!.message).toContain(SIGN_IN);
    });
  });

  test.each<[string, Record<string, unknown>]>([
    ['absent', { protected_resources: GOOD.protected_resources }],
    ['an empty list', { ...GOOD, scopes_supported: [] }],
    // A string holds `checkout` as text, and it is still not a list of scopes.
    ['a string and not a list', { ...GOOD, scopes_supported: 'openid orders:read checkout' }],
    ['null', { ...GOOD, scopes_supported: null }],
    ['a list of other scopes', { ...GOOD, scopes_supported: ['openid', 'Orders:Read', 'CHECKOUT'] }],
  ])('names every scope of the config when scopes_supported is %s', async (_name, served) => {
    const issues = await issuesFor(served);

    expect(issues).toHaveLength(1);
    expect(issues[0]!.code).toBe('scopes_not_supported');
    expect(issues[0]!.message).toContain('orders:read');
    expect(issues[0]!.message).toContain('checkout');
  });

  test.each([
    ['no scopes', undefined],
    ['an empty scopes object', {}],
  ])('does not look at scopes_supported for a config with %s', async (_name, scopes) => {
    const config = createPoppyConfig();
    config.scopes = scopes;

    expect(await issuesFor({ protected_resources: [RESOURCE] }, { config })).toStrictEqual([]);
  });

  test('gives the issue about the resource first and the issue about the scopes second', async () => {
    const issues = await issuesFor({});

    expect(issues.map(({ code }) => code)).toStrictEqual(['protected_resource_missing', 'scopes_not_supported']);
  });

  test('gives the issues about the override first and the issues about the metadata after them', async () => {
    const issues = await issuesFor({}, { protectedResource: { resource: 'https://shop.zepto.example' } });

    expect(issues.map(({ code }) => code)).toStrictEqual([
      'protected_resource_override_mismatch',
      'protected_resource_missing',
      'scopes_not_supported',
    ]);
  });

  test('gives metadata_unavailable, and does not reject, when Auth0 answers with a server error', async () => {
    const issues = await issuesFor(undefined);

    expect(issues).toStrictEqual([{ code: 'metadata_unavailable', message: expect.any(String) }]);
  });

  test('gives metadata_unavailable when the request for the metadata cannot be made', async () => {
    server.use(http.get(`https://${POPPY_DOMAIN}/.well-known/openid-configuration`, () => HttpResponse.error()));

    expect((await createClient().verifyConfig()).map(({ code }) => code)).toStrictEqual(['metadata_unavailable']);
  });

  // The messages are fixed texts. They name the scopes and the resource of the config, and never a value from the
  // metadata of Auth0 or from the override.
  test('the messages are fixed texts that hold nothing from the metadata', async () => {
    const issues = await issuesFor(
      { protected_resources: ['https://canary.example'], scopes_supported: ['canary:scope'] },
      {
        protectedResource: {
          resource: 'https://canary-resource.example',
          authorization_servers: ['https://canary-server.example/'],
        },
      }
    );

    expect(issues.map(({ code, message }) => [code, message])).toStrictEqual([
      [
        'protected_resource_override_mismatch',
        'protectedResource.resource is not exactly https://zepto.example. Agents do not use the oauth-protected-resource document unless its resource is exactly that.',
      ],
      [
        'protected_resource_override_mismatch',
        'protectedResource.authorization_servers does not list the issuer of the config exactly as written there, trailing slash included. Agents do not use the oauth-protected-resource document without it.',
      ],
      [
        'protected_resource_missing',
        "Auth0's metadata does not list https://zepto.example in protected_resources. Agents do not use poppy.json until the issuer lists it there.",
      ],
      [
        'scopes_not_supported',
        "Auth0's metadata does not list these scopes in scopes_supported: orders:read, checkout. The issuer should list every scope that an agent can request.",
      ],
    ]);

    metadata = undefined;
    expect(await createClient().verifyConfig()).toStrictEqual([
      {
        code: 'metadata_unavailable',
        message:
          "Auth0's metadata could not be read, so the config was not compared with it. Check the domain and the network, then run the check again.",
      },
    ]);
  });
});

describe('the package entry point', () => {
  // Types have no runtime value: `npm run typecheck` checks these.
  test('exports the discovery types', () => {
    expectTypeOf<PoppyDiscoveryDocument>().toEqualTypeOf<{
      status: number;
      headers: Record<string, string>;
      body: string;
    }>();
    expectTypeOf<PoppyConfigIssue>().toEqualTypeOf<{ code: PoppyConfigIssueCode; message: string }>();
    expectTypeOf<PoppyConfigIssueCode>().toEqualTypeOf<
      | 'metadata_unavailable'
      | 'protected_resource_missing'
      | 'scopes_not_supported'
      | 'protected_resource_override_mismatch'
    >();
    expectTypeOf<ServerPoppyClient['getDiscoveryDocument']>().toEqualTypeOf<
      (path: string) => PoppyDiscoveryDocument | undefined
    >();
    expectTypeOf<ServerPoppyClient['verifyConfig']>().toEqualTypeOf<() => Promise<PoppyConfigIssue[]>>();
  });

  test('does not export the functions that build and check the documents', () => {
    expect(sdk).not.toHaveProperty('buildDiscoveryDocuments');
    expect(sdk).not.toHaveProperty('findOverrideIssues');
    expect(sdk).not.toHaveProperty('findConfigIssues');
  });
});
