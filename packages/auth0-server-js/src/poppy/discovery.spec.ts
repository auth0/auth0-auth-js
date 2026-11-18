import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, expectTypeOf, test } from 'vitest';
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
  createPoppyFile,
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

// The bodies for the Zepto config, character for character. `poppy.json` is the file as written, so the order of its
// keys is the one of `test-utils/poppy-config.json`, which is the order that the CLI writes.
const POPPY_JSON =
  '{"protocol_version":"1.0","organization":{"name":"Zepto","domain":"zepto.example"},"auth":{"issuer":"https://auth.zepto.example/","scopes":{"orders:read":"orders:read","checkout":"checkout","poppy:browser-sign-in":"poppy:browser-sign-in"},"scope_hints":{"orders:read":{"changes":"none","personal_data":true},"checkout":{"changes":"irreversible","personal_data":true},"poppy:browser-sign-in":{"changes":"none","personal_data":false}}},"apis":[{"type":"openapi","url":"https://zepto.example/openapi.json","description":"https://zepto.example"}],"web":{"browser_session_endpoint":"https://auth.zepto.example/poppy/web_app_client/browser-session","unscoped":false}}';
const INFERRED = '{"resource":"https://zepto.example","authorization_servers":["https://auth.zepto.example/"]}';

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

// The file is the one that the CLI wrote, and the package serves it as it is. It builds nothing from the members, so a
// member that the package does not know, such as one that a later version of the protocol or of the CLI adds, is served
// too, and nothing is checked in it but the domain and the issuer.
describe('poppy.getDiscoveryDocument | poppy.json is the config as written', () => {
  const poppyJsonOf = (config: PoppyConfig) => bodyOf(createClient({ config }), POPPY_JSON_PATH);

  test('serves the file after it is parsed from text and written out again, member by member', () => {
    const parsed = JSON.parse(POPPY_JSON);

    expect(poppyJsonOf(parsed)).toBe(POPPY_JSON);
    expect(JSON.parse(poppyJsonOf(parsed))).toStrictEqual(createPoppyConfig());
  });

  test('serves the members that the package does not know, at every level', () => {
    const file = createPoppyFile();

    Object.assign(file, { extra: 1, more: { list: [1, { deep: true }], none: null } });
    Object.assign(file.organization, { extra: 'x' });
    Object.assign(file.auth, { extra: 'x' });
    Object.assign(file.auth.scopes, { 'admin:all': 'admin:all' });
    Object.assign(file.apis[0]!, { extra: 'x' });
    Object.assign(file.web, { extra: 'x' });

    const body = poppyJsonOf(file);

    expect(body).toBe(JSON.stringify(file));
    expect(JSON.parse(body)).toMatchObject({
      extra: 1,
      more: { list: [1, { deep: true }], none: null },
      organization: { extra: 'x' },
      auth: { extra: 'x', scopes: { 'admin:all': 'admin:all' } },
      apis: [{ extra: 'x' }],
      web: { extra: 'x' },
    });
  });

  test('keeps the order of the members, at every level, as the file has it', () => {
    const text =
      '{"web":{"unscoped":true,"browser_session_endpoint":"https://auth.zepto.example/poppy/c/browser-session"},' +
      '"auth":{"scopes":{"b":"b","a":"a"},"issuer":"https://auth.zepto.example/"},' +
      '"organization":{"domain":"zepto.example","name":"Zepto"},"protocol_version":"1.0"}';

    expect(poppyJsonOf(JSON.parse(text))).toBe(text);
  });

  // The package does not know which versions exist, and it does not need the member to serve the file.
  test.each(['1.0', '1.1', '2.5', 'draft'])('serves a protocol_version of %s as it is', (version) => {
    const file = createPoppyFile();
    file.protocol_version = version;

    expect(poppyJsonOf(file)).toBe(JSON.stringify(file));
    expect(JSON.parse(poppyJsonOf(file)).protocol_version).toBe(version);
  });

  test('serves a file with only the two members that the package reads', () => {
    const minimal = {
      organization: { domain: 'zepto.example' },
      auth: { issuer: POPPY_ISSUER },
    };

    expect(poppyJsonOf(minimal)).toBe(
      '{"organization":{"domain":"zepto.example"},"auth":{"issuer":"https://auth.zepto.example/"}}'
    );
  });

  test('serves web.unscoped as the file has it, and nothing when the file has none', () => {
    for (const unscoped of [true, false]) {
      const file = createPoppyFile();
      file.web.unscoped = unscoped;

      expect(JSON.parse(poppyJsonOf(file)).web.unscoped).toBe(unscoped);
    }

    const file = createPoppyFile();
    delete (file.web as Record<string, unknown>).unscoped;

    expect(JSON.parse(poppyJsonOf(file)).web).toStrictEqual({
      browser_session_endpoint: 'https://auth.zepto.example/poppy/web_app_client/browser-session',
    });
  });

  test('serves a __proto__ member of parsed JSON as data, and does not change the prototype of anything', () => {
    const text =
      '{"organization":{"domain":"zepto.example"},' +
      '"auth":{"issuer":"https://auth.zepto.example/","scopes":{"__proto__":"odd"}},"__proto__":{"polluted":true}}';

    expect(poppyJsonOf(JSON.parse(text))).toBe(text);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  // The `ServerClient` copies the object when it is created, and the body is text made then. A change after that cannot
  // reach it, however deep it is.
  test('a later change of the object by the app does not reach the file', () => {
    const file = createPoppyFile();
    const client = createClient({ config: file });
    const served = bodyOf(client, POPPY_JSON_PATH);

    file.protocol_version = '9.9';
    file.organization.domain = 'evil.example';
    file.auth.issuer = 'https://evil.example/';
    file.auth.scopes['orders:read'] = 'changed';
    file.apis.length = 0;
    file.web.unscoped = true;
    Object.assign(file, { added: true });

    expect(served).toBe(POPPY_JSON);
    expect(bodyOf(client, POPPY_JSON_PATH)).toBe(POPPY_JSON);
  });

  test('oauth-protected-resource does not depend on the members that the package does not read', () => {
    const file = createPoppyFile();
    Object.assign(file, { extra: 1 });
    file.protocol_version = '2.5';
    file.web.unscoped = true;
    file.apis.length = 0;

    expect(bodyOf(createClient({ config: file }), PROTECTED_RESOURCE_PATH)).toBe(INFERRED);
  });

  test('oauth-protected-resource is built from organization.domain, with its port, and from auth.issuer', () => {
    const file = createPoppyFile();
    file.organization.domain = 'shop.zepto.example:8443';

    expect(bodyOf(createClient({ config: file }), PROTECTED_RESOURCE_PATH)).toBe(
      '{"resource":"https://shop.zepto.example:8443","authorization_servers":["https://auth.zepto.example/"]}'
    );
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
    const config = createPoppyFile();
    const client = createClient({ config });

    config.organization.domain = 'evil.example';
    config.auth.issuer = 'https://evil.example/';
    config.auth.scopes['orders:read'] = 'Changed.';
    config.web.browser_session_endpoint = 'https://evil.example/browser-session';
    config.apis.length = 0;

    expect(bodyOf(client, POPPY_JSON_PATH)).toBe(POPPY_JSON);
    expect(bodyOf(client, PROTECTED_RESOURCE_PATH)).toBe(INFERRED);
  });

  // `parseLoginInitiation()` and `verifyConfig()` read the config when they are called, so they are asked after the
  // change.
  test('keeps what parseLoginInitiation accepts, and what verifyConfig reads, when the app changes the config', async () => {
    metadata = {
      scopes_supported: ['openid', 'orders:read', 'checkout', 'poppy:browser-sign-in'],
      protected_resources: [RESOURCE],
    };
    const config = createPoppyFile();
    const client = createClient({ config });

    config.auth.issuer = 'https://evil.example/';
    config.organization.domain = 'evil.example';
    Object.assign(config.auth.scopes, { 'admin:all': 'admin:all' });

    const target = encodeURIComponent(`${RESOURCE}/cart`);
    const loginWith = (iss: string) =>
      new URL(`${RESOURCE}/login?iss=${encodeURIComponent(iss)}&target_link_uri=${target}`);
    // The issuer of the config when the client was made is still the one that is accepted, so its login gets a
    // `returnTo`. The new one is not the issuer, so its login is ignored and gets none.
    expect(client.parseLoginInitiation(loginWith(POPPY_ISSUER), { appOrigin: RESOURCE })).toStrictEqual({
      returnTo: `${RESOURCE}/cart`,
      authorizationParams: {},
    });
    expect(client.parseLoginInitiation(loginWith('https://evil.example/'), { appOrigin: RESOURCE })).toStrictEqual({
      authorizationParams: {},
    });
    // The metadata lists the resource and the scopes of the config as it was. A client that read the changed object
    // would report the new resource and the new scope as missing.
    expect(await client.verifyConfig()).toStrictEqual([]);
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
  const GOOD = {
    scopes_supported: ['openid', 'orders:read', 'checkout', 'poppy:browser-sign-in'],
    protected_resources: [RESOURCE],
  };

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

  // A website that offers a browser join has to support `poppy:browser-sign-in`, so Auth0 should list it, whatever
  // scopes the file has. The scopes of the file are the keys of `auth.scopes`.
  describe('poppy:browser-sign-in', () => {
    const SIGN_IN = 'poppy:browser-sign-in';
    const listing = (...scopes: string[]) => ({
      protected_resources: [RESOURCE],
      scopes_supported: ['openid', 'orders:read', 'checkout', ...scopes],
    });

    // The scopes of the file, as `auth.scopes` of the config. `undefined` leaves the member out.
    const configWithScopes = (scopes: unknown): PoppyConfig => {
      const config = createPoppyConfig();

      if (scopes === undefined) {
        delete config.auth.scopes;
      } else {
        config.auth.scopes = scopes;
      }

      return config;
    };

    test('names it when Auth0 does not list it', async () => {
      const issues = await issuesFor(listing());

      expect(issues).toHaveLength(1);
      expect(issues[0]!.code).toBe('scopes_not_supported');
      expect(issues[0]!.message).toContain(SIGN_IN);
      // The other scopes of the file are listed, so only the new scope is named.
      expect(issues[0]!.message).not.toContain('orders:read');
      expect(issues[0]!.message).not.toContain('checkout');
    });

    test('gives no issue when Auth0 lists it', async () => {
      expect(await issuesFor(listing(SIGN_IN))).toStrictEqual([]);
    });

    test('names it after the scopes of the file, in one issue', async () => {
      const config = configWithScopes({ 'orders:read': 'orders:read', checkout: 'checkout' });
      const issues = await issuesFor({ protected_resources: [RESOURCE], scopes_supported: ['openid'] }, { config });

      expect(issues).toHaveLength(1);
      expect(issues[0]!.message).toContain(`these scopes: orders:read, checkout, ${SIGN_IN}.`);
    });

    test('names it once when the file lists it as a scope too', async () => {
      const issues = await issuesFor({ protected_resources: [RESOURCE], scopes_supported: ['openid'] });

      expect(issues).toHaveLength(1);
      expect(issues[0]!.message).toContain(`these scopes: orders:read, checkout, ${SIGN_IN}.`);
      expect(issues[0]!.message.split(SIGN_IN)).toHaveLength(2);
    });

    test.each<[string, unknown]>([
      ['no scopes', undefined],
      ['an empty scopes object', {}],
      ['a string and not an object', 'orders:read'],
      ['a list and not an object', ['orders:read', 'checkout']],
      ['null', null],
      ['a number', 7],
    ])('is the only scope that is looked for when the file has %s', async (_name, scopes) => {
      const issues = await issuesFor(
        { protected_resources: [RESOURCE], scopes_supported: ['openid'] },
        { config: configWithScopes(scopes) }
      );

      expect(issues.map(({ code }) => code)).toStrictEqual(['scopes_not_supported']);
      expect(issues[0]!.message).toContain('these scopes: poppy:browser-sign-in.');
    });

    test.each<[string, Record<string, unknown>]>([
      ['absent', { protected_resources: [RESOURCE] }],
      ['a string and not a list', { protected_resources: [RESOURCE], scopes_supported: `openid ${SIGN_IN}` }],
      ['null', { protected_resources: [RESOURCE], scopes_supported: null }],
      ['in another case', { protected_resources: [RESOURCE], scopes_supported: ['Poppy:Browser-Sign-In'] }],
    ])('names it when scopes_supported is %s', async (_name, served) => {
      const issues = await issuesFor(served, { config: configWithScopes(undefined) });

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

  // The agent uses the scopes of both lists (spec sections 3.2 and 4.7), so a scope that only the served
  // oauth-protected-resource document lists is listed.
  describe('scopes_supported of the protectedResource option', () => {
    const ALL = ['orders:read', 'checkout', 'poppy:browser-sign-in'];
    const onlyResource = { protected_resources: [RESOURCE], scopes_supported: ['openid'] };

    test('gives no issue when the option lists every scope and the metadata lists none', async () => {
      expect(await issuesFor(onlyResource, { protectedResource: { scopes_supported: ALL } })).toStrictEqual([]);
    });

    test('names only the scopes that neither list has', async () => {
      const issues = await issuesFor(
        { ...onlyResource, scopes_supported: ['openid', 'orders:read'] },
        { protectedResource: { scopes_supported: ['checkout'] } }
      );

      expect(issues).toHaveLength(1);
      expect(issues[0]!.code).toBe('scopes_not_supported');
      expect(issues[0]!.message).toContain('these scopes: poppy:browser-sign-in.');
      expect(issues[0]!.message).not.toContain('orders:read');
      expect(issues[0]!.message).not.toContain('checkout');
    });

    test.each<[string, unknown]>([
      ['a string and not a list', ALL.join(' ')],
      ['null', null],
      ['an object and not a list', { 0: 'orders:read' }],
    ])('lists nothing when scopes_supported of the option is %s', async (_name, scopes) => {
      const issues = await issuesFor(onlyResource, { protectedResource: { scopes_supported: scopes } });

      expect(issues.map(({ code }) => code)).toStrictEqual(['scopes_not_supported']);
      expect(issues[0]!.message).toContain('these scopes: orders:read, checkout, poppy:browser-sign-in.');
    });

    test('does not put a value of the option in the message', async () => {
      const issues = await issuesFor(onlyResource, { protectedResource: { scopes_supported: ['secret-scope'] } });

      expect(issues).toHaveLength(1);
      expect(issues[0]!.message).not.toContain('secret-scope');
    });
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
        "No scopes_supported list names these scopes: orders:read, checkout, poppy:browser-sign-in. Agents use the scopes_supported of Auth0's metadata and of the oauth-protected-resource document, so one of them should list every scope that an agent can request.",
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
