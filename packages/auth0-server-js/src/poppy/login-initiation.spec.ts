import { describe, expect, expectTypeOf, test, vi } from 'vitest';
import { IssuerValidationError } from '../errors.js';
import type { ParseLoginInitiationOptions, PoppyLoginInitiation } from '../index.js';
import { ServerClient } from '../server-client.js';
import { POPPY_CLIENT_ID, POPPY_DOMAIN, POPPY_ISSUER, createPoppyConfig } from '../test-utils/poppy.js';
import type { ServerPoppyClient } from './server-poppy-client.js';

// After a browser join, Auth0 sends the agent's browser to the login route of the website with `iss` and
// `target_link_uri`. `parseLoginInitiation` is the check that the route makes on that request. These tests call it
// through a `ServerClient`, as an app does. It needs no store and no network: the request is a URL, and the answer
// is data.

const APP_ORIGIN = 'https://zepto.example';
const LOGIN_URL = 'https://zepto.example/auth/login';
const MISMATCH = 'The iss parameter of the login request does not match the issuer of this application.';

const stubStore = () => ({ get: vi.fn(), set: vi.fn(), delete: vi.fn() });

// A poppy client for a domain. `issuer` is the issuer in the config, which the `iss` of a request is compared with.
function poppyFor(domain: string, issuer: string): ServerPoppyClient {
  const client = new ServerClient({
    domain,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    transactionStore: stubStore(),
    stateStore: { ...stubStore(), deleteByLogoutToken: vi.fn() },
    poppy: { config: { ...createPoppyConfig(), issuer }, guestStore: stubStore() },
  });

  return client.poppy;
}

const poppy = poppyFor(POPPY_DOMAIN, POPPY_ISSUER);

type Query = Array<[name: string, value: string]>;

// The login request, with the query in the order given. A name can repeat, as it can in a real request.
function request(query: Query): URL {
  const url = new URL(LOGIN_URL);

  for (const [name, value] of query) {
    url.searchParams.append(name, value);
  }

  return url;
}

const parse = (query: Query, appOrigin = APP_ORIGIN) => poppy.parseLoginInitiation(request(query), { appOrigin });

// The `returnTo` for a `target_link_uri`, in a request with the right `iss`, as Auth0 sends it.
const returnToFor = (target: string, appOrigin = APP_ORIGIN) =>
  parse(
    [
      ['iss', POPPY_ISSUER],
      ['target_link_uri', target],
    ],
    appOrigin
  ).returnTo;

const thrownBy = (fn: () => unknown): unknown => {
  try {
    fn();
  } catch (error) {
    return error;
  }
};

describe('poppy.parseLoginInitiation | iss', () => {
  test('accepts a request with no iss', () => {
    expect(parse([])).toStrictEqual({ authorizationParams: {} });
  });

  test('accepts the issuer of the config', () => {
    expect(parse([['iss', POPPY_ISSUER]])).toStrictEqual({ authorizationParams: {} });
  });

  test('accepts the issuer written as a browser sends it, with the characters escaped', () => {
    const url = new URL(`${LOGIN_URL}?iss=${encodeURIComponent(POPPY_ISSUER)}`);

    expect(url.search).toBe('?iss=https%3A%2F%2Fauth.zepto.example%2F');
    expect(poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toStrictEqual({ authorizationParams: {} });
  });

  test.each([
    ['no trailing slash', 'https://auth.zepto.example'],
    ['another case', 'https://AUTH.zepto.example/'],
    ['another issuer', 'https://evil.example/'],
    ['an empty value', ''],
    ['a space after the issuer', `${POPPY_ISSUER} `],
    ['the issuer of a longer host', 'https://auth.zepto.example.evil.example/'],
  ])('refuses an iss with %s', (_what, iss) => {
    expect(() => parse([['iss', iss]])).toThrowError(IssuerValidationError);
    expect(() => parse([['iss', iss]])).toThrowError(MISMATCH);
  });

  test('refuses an iss with no value at all', () => {
    const url = new URL(`${LOGIN_URL}?iss`);

    expect(() => poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toThrowError(IssuerValidationError);
  });

  test.each([
    ['the issuer twice', [POPPY_ISSUER, POPPY_ISSUER]],
    ['the issuer and then another value', [POPPY_ISSUER, 'https://evil.example/']],
    ['another value and then the issuer', ['https://evil.example/', POPPY_ISSUER]],
  ])('refuses a repeated iss: %s', (_what, values) => {
    const query = values.map((value): [string, string] => ['iss', value]);

    expect(() => parse(query)).toThrowError(IssuerValidationError);
  });

  // A check that looks at the raw text of the query for `iss=` would miss this name.
  test('refuses an iss whose name is written with an escape', () => {
    const url = new URL(`${LOGIN_URL}?%69ss=https%3A%2F%2Fevil.example%2F`);

    expect(() => poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toThrowError(IssuerValidationError);
  });

  test('refuses a wrong iss even when the target_link_uri is fine', () => {
    expect(() =>
      parse([
        ['iss', 'https://evil.example/'],
        ['target_link_uri', 'https://zepto.example/cart'],
      ])
    ).toThrowError(IssuerValidationError);
  });

  test('throws an error with a name, a code and a fixed message that does not show the value', () => {
    const error = thrownBy(() => parse([['iss', 'https://leak-check.example/']])) as IssuerValidationError;

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(IssuerValidationError);
    expect(error.name).toBe('IssuerValidationError');
    expect(error.code).toBe('issuer_validation_error');
    expect(error.message).toBe(MISMATCH);
    expect(error.message).not.toContain('leak-check');
  });

  // The `domain` option can be written in more than one way. The issuer is one text, and the iss is compared with it as
  // it is: a spelling of the domain is not an issuer, and neither is the issuer with another case or no slash.
  test.each(['auth.zepto.example', 'https://auth.zepto.example', 'AUTH.zepto.example'])(
    'compares iss with the one issuer when the domain is written as %s',
    (domain) => {
      const client = poppyFor(domain, POPPY_ISSUER);
      const withIssuer = (iss: string) =>
        client.parseLoginInitiation(request([['iss', iss]]), { appOrigin: APP_ORIGIN });

      expect(withIssuer(POPPY_ISSUER)).toStrictEqual({ authorizationParams: {} });
      expect(() => withIssuer(domain)).toThrowError(IssuerValidationError);
      expect(() => withIssuer('https://AUTH.zepto.example/')).toThrowError(IssuerValidationError);
      expect(() => withIssuer('https://auth.zepto.example')).toThrowError(IssuerValidationError);
    }
  );

  test('compares with the issuer of the config of the client, not a fixed one', () => {
    const other = poppyFor('login.other.example', 'https://login.other.example/');
    const withIssuer = (iss: string) => other.parseLoginInitiation(request([['iss', iss]]), { appOrigin: APP_ORIGIN });

    expect(withIssuer('https://login.other.example/')).toStrictEqual({ authorizationParams: {} });
    expect(() => withIssuer(POPPY_ISSUER)).toThrowError(IssuerValidationError);
  });
});

describe('poppy.parseLoginInitiation | returnTo', () => {
  test.each(['https://zepto.example/cart?x=1#top', 'https://zepto.example//evil.example/x'])(
    'keeps %s as it is',
    (target) => {
      expect(returnToFor(target)).toBe(target);
    }
  );

  test('gives no returnTo key when there is no target_link_uri', () => {
    expect(parse([['iss', POPPY_ISSUER]])).toStrictEqual({ authorizationParams: {} });
  });

  // The URL that is checked is the URL that is returned. The parser writes it in its own form, so the value that a
  // route redirects to has no tab, no line break, no backslash and no dot segment to be read in another way.
  test.each([
    [
      'an upper-case scheme and host, the default port and dot segments',
      'HTTPS://ZEPTO.EXAMPLE:443/a/../cart',
      'https://zepto.example/cart',
    ],
    ['an origin with no path', 'https://zepto.example', 'https://zepto.example/'],
    ['a tab in the path', 'https://zepto.example/ca\trt', 'https://zepto.example/cart'],
    ['line breaks in the host and the path', 'https://zepto\n.example/ca\nrt', 'https://zepto.example/cart'],
    ['spaces around the value', ' https://zepto.example/cart ', 'https://zepto.example/cart'],
    ['a backslash after the host', 'https://zepto.example\\evil.example', 'https://zepto.example/evil.example'],
    ['a backslash before an @', 'https://zepto.example\\@evil.example/', 'https://zepto.example/@evil.example/'],
    ['escaped dot segments', 'https://zepto.example/%2e%2e/%2e%2e/x', 'https://zepto.example/x'],
    ['a space in the path', 'https://zepto.example/my cart', 'https://zepto.example/my%20cart'],
    ['a scheme with no slashes', 'https:zepto.example/cart', 'https://zepto.example/cart'],
    [
      'full-width letters in the host',
      'https://\uFF5A\uFF45\uFF50\uFF54\uFF4F.example/cart',
      'https://zepto.example/cart',
    ],
  ])('writes %s as the URL parser does', (_what, target, expected) => {
    const returnTo = returnToFor(target);

    expect(returnTo).toBe(expected);
    expect(new URL(returnTo!).origin).toBe(APP_ORIGIN);
  });

  // Open redirect: each of these must leave the website without a landing page, and with no error.
  test.each([
    ['another site', 'https://evil.example/'],
    ['a host that starts with the origin', 'https://zepto.example.evil.example/'],
    ['credentials that make the site look like the user name', 'https://zepto.example@evil.example/'],
    ['the site in the path of another site', 'https://evil.example/https://zepto.example/'],
    ['a backslash that ends the host of another site', 'https://evil.example\\@zepto.example/'],
    ['a scheme with no slashes, for another site', 'https:evil.example'],
    ['a slash and a backslash, for another site', 'https:/\\evil.example'],
    ['a full stop after the host', 'https://zepto.example./cart'],
    ['a host that looks like the site (a Cyrillic e)', 'https://z\u0435pto.example/'],
    // The text starts with the origin, but the parser first removes the tab or the line break, so the host is another.
    ['a tab that joins the site to another host', 'https://zepto.example\t.evil.example/'],
    ['a line break before an @', 'https://zepto.example\n@evil.example/'],
    ['an http page, for an https site', 'http://zepto.example/'],
    ['another port', 'https://zepto.example:8443/'],
    ['ws with the same host', 'wss://zepto.example/x'],
    ['ftp with the same host', 'ftp://zepto.example/x'],
    ['a blob URL, which has the origin of the site that made it', 'blob:https://zepto.example/6f1a2b3c'],
    ['a path', '/cart'],
    ['a scheme-relative URL', '//evil.example/'],
    ['a scheme-relative URL with a backslash', '/\\evil.example'],
    ['a relative path', 'cart'],
    ['an empty value', ''],
    ['spaces only', '   '],
    ['a script', 'javascript:alert(1)'],
    ['a script with a line break in the scheme', 'java\nscript:alert(1)'],
    ['a data URL', 'data:text/html,hi'],
    ['a file URL', 'file:///etc/passwd'],
    ['an escaped scheme', '%68ttps://zepto.example/'],
    ['a user name on the site', 'https://ana@zepto.example/cart'],
    ['a user name and password on the site', 'https://ana:secret@zepto.example/cart'],
  ])('ignores %s', (_what, target) => {
    expect(
      parse([
        ['iss', POPPY_ISSUER],
        ['target_link_uri', target],
      ])
    ).toStrictEqual({ authorizationParams: {} });
  });

  test.each([
    ['twice, both on the site', ['https://zepto.example/a', 'https://zepto.example/b']],
    ['twice with the same value', ['https://zepto.example/a', 'https://zepto.example/a']],
    ['twice, a good value and then another site', ['https://zepto.example/cart', 'https://evil.example/']],
    ['twice, another site and then a good value', ['https://evil.example/', 'https://zepto.example/cart']],
  ])('ignores a target_link_uri that appears %s', (_what, values) => {
    const query = values.map((value): [string, string] => ['target_link_uri', value]);

    expect(parse(query)).toStrictEqual({ authorizationParams: {} });
  });

  test('reads the name target_link_uri after the escapes are decoded', () => {
    const url = new URL(
      `${LOGIN_URL}?target_link_uri=https%3A%2F%2Fzepto.example%2Fa&%74arget_link_uri=https%3A%2F%2Fzepto.example%2Fb`
    );

    expect(poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toStrictEqual({ authorizationParams: {} });
  });
});

describe('poppy.parseLoginInitiation | appOrigin', () => {
  test.each(['https://zepto.example/', 'https://zepto.example/shop?x=1#y', 'HTTPS://Zepto.Example:443'])(
    'uses only the origin of %s',
    (appOrigin) => {
      expect(returnToFor('https://zepto.example/cart?x=1#top', appOrigin)).toBe('https://zepto.example/cart?x=1#top');
      expect(returnToFor('https://zepto.example//evil.example/x', appOrigin)).toBe(
        'https://zepto.example//evil.example/x'
      );
      expect(returnToFor('https://evil.example/', appOrigin)).toBeUndefined();
      expect(returnToFor('https://zepto.example.evil.example/', appOrigin)).toBeUndefined();
      expect(returnToFor('http://zepto.example/', appOrigin)).toBeUndefined();
      expect(returnToFor('https://zepto.example:8443/', appOrigin)).toBeUndefined();
    }
  );

  test('works for a site on http, such as a local one, and only for the same scheme and port', () => {
    const local = 'http://localhost:3000';

    expect(returnToFor('http://localhost:3000/cart', local)).toBe('http://localhost:3000/cart');
    expect(returnToFor('https://localhost:3000/cart', local)).toBeUndefined();
    expect(returnToFor('http://localhost:3001/cart', local)).toBeUndefined();
    expect(returnToFor('http://localhost/cart', local)).toBeUndefined();
  });

  // `localhost:3000` is a URL with the scheme `localhost:`, and its origin is opaque. An opaque origin equals another
  // opaque origin, so a check that only compares origins would accept a script URL.
  test.each(['localhost:3000', 'zepto.example:8443', 'javascript:void(0)', 'data:,', 'about:blank', 'file:///app'])(
    'never gives a returnTo when appOrigin %s is not a web origin',
    (appOrigin) => {
      expect(returnToFor('javascript:alert(1)', appOrigin)).toBeUndefined();
      expect(returnToFor('data:text/html,hi', appOrigin)).toBeUndefined();
      expect(returnToFor(appOrigin, appOrigin)).toBeUndefined();
      expect(returnToFor('https://zepto.example/cart', appOrigin)).toBeUndefined();
    }
  );

  // A wrong appOrigin is a mistake of the app. It must stop every request, not hide until a request has a target.
  test.each(['', 'zepto.example'])(
    'throws a TypeError for the appOrigin %j, with or without a target_link_uri',
    (appOrigin) => {
      expect(() => parse([], appOrigin)).toThrowError(TypeError);
      expect(() => returnToFor('https://zepto.example/cart', appOrigin)).toThrowError(TypeError);
    }
  );
});

describe('poppy.parseLoginInitiation | authorizationParams', () => {
  test('gives every other parameter, one value each (the last), without iss and target_link_uri', () => {
    const result = parse([
      ['iss', POPPY_ISSUER],
      ['target_link_uri', 'https://zepto.example/cart'],
      ['login_hint', 'ana@zepto.example'],
      ['foo', '1'],
      ['foo', '2'],
    ]);

    expect(result).toStrictEqual({
      returnTo: 'https://zepto.example/cart',
      authorizationParams: { login_hint: 'ana@zepto.example', foo: '2' },
    });
  });

  test('is an empty object when the request has no other parameter', () => {
    expect(
      parse([
        ['iss', POPPY_ISSUER],
        ['target_link_uri', 'https://zepto.example/cart'],
      ]).authorizationParams
    ).toStrictEqual({});
  });

  test('does not give target_link_uri when the value is ignored', () => {
    const { authorizationParams } = parse([
      ['target_link_uri', 'https://evil.example/'],
      ['target_link_uri', 'https://zepto.example/cart'],
      ['screen_hint', 'signup'],
    ]);

    expect(authorizationParams).toStrictEqual({ screen_hint: 'signup' });
  });

  test('reads the values as a browser form does', () => {
    const url = new URL(`${LOGIN_URL}?screen_hint=sign+up&ui_locales=en%20GB&prompt=&flag`);

    expect(poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN }).authorizationParams).toStrictEqual({
      screen_hint: 'sign up',
      ui_locales: 'en GB',
      prompt: '',
      flag: '',
    });
  });

  test('keeps the names of other parameters as they are, case included', () => {
    const { authorizationParams } = parse([
      ['ISS', 'https://evil.example/'],
      ['Target_Link_Uri', 'https://evil.example/'],
    ]);

    expect(authorizationParams).toStrictEqual({
      ISS: 'https://evil.example/',
      Target_Link_Uri: 'https://evil.example/',
    });
  });

  // The names come from the query of a request, so they can be any text. A name like `__proto__` is plain data.
  test('keeps a parameter named __proto__ as plain data and does not change any prototype', () => {
    const { authorizationParams } = parse([
      ['__proto__', 'polluted'],
      ['constructor', 'x'],
    ]);

    expect(Object.getPrototypeOf(authorizationParams)).toBe(Object.prototype);
    expect(Object.keys(authorizationParams)).toStrictEqual(['__proto__', 'constructor']);
    expect(Object.entries(authorizationParams)).toStrictEqual([
      ['__proto__', 'polluted'],
      ['constructor', 'x'],
    ]);
    expect({}).not.toHaveProperty('polluted');
  });
});

describe('poppy.parseLoginInitiation | the API', () => {
  test('answers at once, not with a promise', () => {
    expect(parse([])).not.toBeInstanceOf(Promise);
  });

  test('does not change the URL it is given', () => {
    const url = request([
      ['iss', POPPY_ISSUER],
      ['target_link_uri', 'https://zepto.example/cart'],
      ['foo', '1'],
    ]);
    const before = url.href;

    poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN });

    expect(url.href).toBe(before);
  });

  // Types have no runtime value: `npm run typecheck` checks these.
  test('exports the types', () => {
    expectTypeOf<ParseLoginInitiationOptions>().toEqualTypeOf<{ appOrigin: string }>();
    expectTypeOf<PoppyLoginInitiation['returnTo']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<PoppyLoginInitiation['authorizationParams']>().toEqualTypeOf<Record<string, string>>();
    expectTypeOf<ServerPoppyClient['parseLoginInitiation']>().toEqualTypeOf<
      (url: URL, options: ParseLoginInitiationOptions) => PoppyLoginInitiation
    >();
  });
});
