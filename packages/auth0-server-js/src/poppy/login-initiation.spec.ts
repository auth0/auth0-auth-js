import { afterEach, beforeEach, describe, expect, expectTypeOf, test, vi } from 'vitest';
import type { MockInstance } from 'vitest';
import { IssuerValidationError } from '../index.js';
import type { ParseLoginInitiationOptions, PoppyLoginInitiation } from '../index.js';
import { ServerClient } from '../server-client.js';
import { POPPY_CLIENT_ID, POPPY_DOMAIN, POPPY_ISSUER, createPoppyConfig } from '../test-utils/poppy.js';
import type { ServerPoppyClient } from './server-poppy-client.js';

// After a browser join, Auth0 is expected to send the agent's browser to the login route of the website with `iss` and
// `target_link_uri`. Today's builds add neither. `parseLoginInitiation` is the check that the route makes on that
// request. These tests call it
// through a `ServerClient`, as an app does. It needs no store and no network: the request is a URL, and the answer
// is data. A request with no `iss` is a normal login. A request with an `iss` that is not the issuer of the app says
// that it comes from another issuer, so the method throws an `IssuerValidationError`, and the login does not go on.
// Anyone can send a browser to the login route with any query, so nothing is logged, and the message of the error has
// no value from the request.

const APP_ORIGIN = 'https://zepto.example';
const LOGIN_URL = 'https://zepto.example/auth/login';
const GOOD_TARGET = 'https://zepto.example/cart';

const stubStore = () => ({ get: vi.fn(), set: vi.fn(), delete: vi.fn() });

// A poppy client for a domain. `issuer` is the issuer in the config, which the `iss` of a request is compared with.
function poppyFor(domain: string, issuer: string): ServerPoppyClient {
  const config = createPoppyConfig();
  config.auth.issuer = issuer;

  const client = new ServerClient({
    domain,
    clientId: POPPY_CLIENT_ID,
    clientSecret: '<client_secret>',
    transactionStore: stubStore(),
    stateStore: { ...stubStore(), deleteByLogoutToken: vi.fn() },
    poppy: { config, guestStore: stubStore() },
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

// Every `console` method that a library could log with. None of them may be called by the parse of a request.
let warn: MockInstance<typeof console.warn>;
let otherLogs: Array<MockInstance>;

beforeEach(() => {
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  otherLogs = (['log', 'info', 'debug', 'error', 'trace'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {})
  );
});

afterEach(() => {
  vi.restoreAllMocks();
});

const expectNoLogs = () => {
  expect(warn).not.toHaveBeenCalled();

  for (const log of otherLogs) {
    expect(log).not.toHaveBeenCalled();
  }
};

describe('poppy.parseLoginInitiation | iss that is not there or is the issuer', () => {
  test('accepts a request with no iss, and logs nothing', () => {
    expect(parse([])).toStrictEqual({ authorizationParams: {} });
    expectNoLogs();
  });

  test('accepts the issuer of the config, and logs nothing', () => {
    expect(parse([['iss', POPPY_ISSUER]])).toStrictEqual({ authorizationParams: {} });
    expectNoLogs();
  });

  test('accepts the issuer written as a browser sends it, with the characters escaped', () => {
    const url = new URL(
      `${LOGIN_URL}?iss=${encodeURIComponent(POPPY_ISSUER)}&target_link_uri=${encodeURIComponent(GOOD_TARGET)}`
    );

    expect(url.search).toBe(
      '?iss=https%3A%2F%2Fauth.zepto.example%2F&target_link_uri=https%3A%2F%2Fzepto.example%2Fcart'
    );
    expect(poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toStrictEqual({
      returnTo: GOOD_TARGET,
      authorizationParams: {},
    });
    expectNoLogs();
  });
});

const REFUSED_MESSAGE = 'Invalid iss query parameter: it is not the Auth0 issuer this app uses.';

// The error that a call throws, after the checks that every refusal has to pass: the class, the fixed message, the code,
// and no value of the request in the text of the error.
function refusal(call: () => unknown): IssuerValidationError {
  let thrown: unknown;

  try {
    call();
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(IssuerValidationError);

  const error = thrown as IssuerValidationError;

  expect(error.message).toBe(REFUSED_MESSAGE);
  expect(error.code).toBe('issuer_validation_error');
  expect(error.name).toBe('IssuerValidationError');
  expect(error.cause).toBeUndefined();

  return error;
}

describe('poppy.parseLoginInitiation | iss that is refused', () => {
  // The login says that it comes from another issuer, so it is refused: nothing is returned, so there is no `returnTo`
  // and no other parameter to pass on, and the route starts no login.
  test.each([
    ['no trailing slash', 'https://auth.zepto.example'],
    ['another case', 'https://AUTH.zepto.example/'],
    ['another issuer', 'https://evil.example/'],
    ['an empty value', ''],
    ['a space after the issuer', `${POPPY_ISSUER} `],
    ['the issuer of a longer host', 'https://auth.zepto.example.evil.example/'],
  ])('throws for an iss with %s, and logs nothing', (_what, iss) => {
    refusal(() =>
      parse([
        ['iss', iss],
        ['target_link_uri', GOOD_TARGET],
        ['login_hint', 'ana@zepto.example'],
      ])
    );
    expectNoLogs();
  });

  test('throws for an iss with no value at all, and logs nothing', () => {
    const url = new URL(`${LOGIN_URL}?iss&target_link_uri=${encodeURIComponent(GOOD_TARGET)}&screen_hint=signup`);

    refusal(() => poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN }));
    expectNoLogs();
  });

  test.each([
    ['the issuer twice', [POPPY_ISSUER, POPPY_ISSUER]],
    ['the issuer and then another value', [POPPY_ISSUER, 'https://evil.example/']],
    ['another value and then the issuer', ['https://evil.example/', POPPY_ISSUER]],
    ['three values, the issuer among them', [POPPY_ISSUER, 'https://evil.example/', POPPY_ISSUER]],
  ])('throws for a repeated iss (%s), and logs nothing', (_what, values) => {
    const query: Query = [
      ...values.map((value): [string, string] => ['iss', value]),
      ['target_link_uri', GOOD_TARGET],
      ['login_hint', 'ana@zepto.example'],
    ];

    refusal(() => parse(query));
    expectNoLogs();
  });

  // A check that looks at the raw text of the query for `iss=` would miss this name.
  test('throws for an iss whose name is written with an escape, and logs nothing', () => {
    const url = new URL(
      `${LOGIN_URL}?%69ss=https%3A%2F%2Fevil.example%2F&target_link_uri=${encodeURIComponent(GOOD_TARGET)}&foo=1`
    );

    refusal(() => poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN }));
    expectNoLogs();
  });

  // The `iss` is the check, whatever else the request holds: a good target, a bad one, none, or other parameters.
  test.each([
    ['a good target_link_uri', [['target_link_uri', GOOD_TARGET]]],
    ['another site as the target_link_uri', [['target_link_uri', 'https://evil.example/']]],
    [
      'a target_link_uri that is repeated',
      [
        ['target_link_uri', GOOD_TARGET],
        ['target_link_uri', GOOD_TARGET],
      ],
    ],
    ['no target_link_uri', []],
    ['only other parameters', [['login_hint', 'ana@zepto.example']]],
  ] as Array<[string, Query]>)('throws for a wrong iss with %s', (_what, rest) => {
    refusal(() => parse([['iss', 'https://evil.example/'], ...rest]));
    expectNoLogs();
  });

  // The value of `iss` comes from the request, so it is never in the error. The same goes for every other value in it.
  test('has no value of the request in the error', () => {
    const error = refusal(() =>
      parse([
        ['iss', 'https://leak-check-iss.example/'],
        ['iss', 'https://leak-check-iss-2.example/'],
        ['target_link_uri', 'https://leak-check-target.example/path'],
        ['login_hint', 'leak-check-hint'],
      ])
    );

    for (const text of [error.message, error.stack ?? '', String(error), JSON.stringify(error)]) {
      expect(text).not.toContain('leak-check');
    }
  });

  // Anyone who can send a browser to the login route can set any parameter, so nothing about the request may reach the
  // log of the app, on any call.
  test('logs nothing, whatever the request holds, on every call', () => {
    for (let call = 0; call < 2; call += 1) {
      refusal(() =>
        parse([
          ['iss', 'https://leak-check-iss.example/'],
          ['iss', 'https://leak-check-iss-2.example/'],
          ['target_link_uri', 'https://leak-check-target.example/path'],
          ['login_hint', 'leak-check-hint'],
        ])
      );
    }

    expectNoLogs();
  });

  // The `domain` option can be written in more than one way. The issuer is one text, and the iss is compared with it as
  // it is: a spelling of the domain is not an issuer, and neither is the issuer with another case or no slash.
  test.each(['auth.zepto.example', 'https://auth.zepto.example', 'AUTH.zepto.example'])(
    'compares iss with the one issuer when the domain is written as %s',
    (domain) => {
      const client = poppyFor(domain, POPPY_ISSUER);
      const withIssuer = (iss: string) =>
        client.parseLoginInitiation(
          request([
            ['iss', iss],
            ['target_link_uri', GOOD_TARGET],
          ]),
          { appOrigin: APP_ORIGIN }
        );

      expect(withIssuer(POPPY_ISSUER)).toStrictEqual({ returnTo: GOOD_TARGET, authorizationParams: {} });

      for (const iss of [domain, 'https://AUTH.zepto.example/', 'https://auth.zepto.example']) {
        refusal(() => withIssuer(iss));
      }

      expectNoLogs();
    }
  );

  test('compares with the issuer of the config of the client, not a fixed one', () => {
    const other = poppyFor('login.other.example', 'https://login.other.example/');
    const withIssuer = (iss: string) =>
      other.parseLoginInitiation(
        request([
          ['iss', iss],
          ['target_link_uri', GOOD_TARGET],
        ]),
        { appOrigin: APP_ORIGIN }
      );

    expect(withIssuer('https://login.other.example/')).toStrictEqual({
      returnTo: GOOD_TARGET,
      authorizationParams: {},
    });
    refusal(() => withIssuer(POPPY_ISSUER));
    expectNoLogs();
  });
});

describe('poppy.parseLoginInitiation | returnTo', () => {
  test.each(['https://zepto.example/cart?x=1#top', 'https://zepto.example//evil.example/x'])(
    'keeps %s as it is, when iss is the issuer',
    (target) => {
      expect(returnToFor(target)).toBe(target);
      expectNoLogs();
    }
  );

  test('gives no returnTo key when there is no target_link_uri', () => {
    expect(parse([['iss', POPPY_ISSUER]])).toStrictEqual({ authorizationParams: {} });
  });

  // `target_link_uri` is only read together with an `iss` that is the issuer. Without `iss` there is nothing that says
  // the request comes from Auth0, so the value is ignored. This is not an error, and nothing is logged.
  test.each([
    ['a page of the website', GOOD_TARGET],
    ['another site', 'https://evil.example/'],
    ['an empty value', ''],
  ])('gives no returnTo for a target_link_uri with no iss (%s), and logs nothing', (_what, target) => {
    const result = parse([['target_link_uri', target]]);

    expect(result).toStrictEqual({ authorizationParams: {} });
    expect('returnTo' in result).toBe(false);
    expectNoLogs();
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

  // Open redirect: each of these must leave the website without a landing page, and with no error. The `iss` is right,
  // so it is the target that is not used, and nothing is logged.
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
    expectNoLogs();
  });

  test.each([
    ['twice, both on the site', ['https://zepto.example/a', 'https://zepto.example/b']],
    ['twice with the same value', ['https://zepto.example/a', 'https://zepto.example/a']],
    ['twice, a good value and then another site', ['https://zepto.example/cart', 'https://evil.example/']],
    ['twice, another site and then a good value', ['https://evil.example/', 'https://zepto.example/cart']],
  ])('ignores a target_link_uri that appears %s', (_what, values) => {
    const query: Query = [
      ['iss', POPPY_ISSUER],
      ...values.map((value): [string, string] => ['target_link_uri', value]),
    ];

    expect(parse(query)).toStrictEqual({ authorizationParams: {} });
    expectNoLogs();
  });

  test('reads the name target_link_uri after the escapes are decoded', () => {
    const url = new URL(
      `${LOGIN_URL}?iss=${encodeURIComponent(POPPY_ISSUER)}&target_link_uri=https%3A%2F%2Fzepto.example%2Fa&%74arget_link_uri=https%3A%2F%2Fzepto.example%2Fb`
    );

    expect(poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toStrictEqual({ authorizationParams: {} });
  });

  test('reads the name iss after the escapes are decoded, so an escaped name also gives a returnTo', () => {
    const url = new URL(
      `${LOGIN_URL}?%69ss=${encodeURIComponent(POPPY_ISSUER)}&%74arget_link_uri=${encodeURIComponent(GOOD_TARGET)}`
    );

    expect(poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toStrictEqual({
      returnTo: GOOD_TARGET,
      authorizationParams: {},
    });
    expectNoLogs();
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

  // A wrong appOrigin is a mistake of the app. It must stop every request, not hide until a request has a target. It
  // stops a request whose `iss` is wrong too, and nothing is logged for it.
  test.each(['', 'zepto.example'])(
    'throws a TypeError for the appOrigin %j, with or without a target_link_uri',
    (appOrigin) => {
      expect(() => parse([], appOrigin)).toThrowError(TypeError);
      expect(() => returnToFor(GOOD_TARGET, appOrigin)).toThrowError(TypeError);
      expect(() =>
        parse(
          [
            ['iss', 'https://evil.example/'],
            ['target_link_uri', GOOD_TARGET],
          ],
          appOrigin
        )
      ).toThrowError(TypeError);
      expectNoLogs();
    }
  );
});

describe('poppy.parseLoginInitiation | authorizationParams', () => {
  test('gives every other parameter, one value each (the last), without iss and target_link_uri', () => {
    const result = parse([
      ['iss', POPPY_ISSUER],
      ['target_link_uri', GOOD_TARGET],
      ['login_hint', 'ana@zepto.example'],
      ['foo', '1'],
      ['foo', '2'],
    ]);

    expect(result).toStrictEqual({
      returnTo: GOOD_TARGET,
      authorizationParams: { login_hint: 'ana@zepto.example', foo: '2' },
    });
  });

  test('is an empty object when the request has no other parameter', () => {
    expect(
      parse([
        ['iss', POPPY_ISSUER],
        ['target_link_uri', GOOD_TARGET],
      ]).authorizationParams
    ).toStrictEqual({});
  });

  test('does not give target_link_uri when the value is ignored', () => {
    const { authorizationParams } = parse([
      ['target_link_uri', 'https://evil.example/'],
      ['target_link_uri', GOOD_TARGET],
      ['screen_hint', 'signup'],
    ]);

    expect(authorizationParams).toStrictEqual({ screen_hint: 'signup' });
  });

  test('does not give iss or target_link_uri in any case: accepted, ignored or missing', () => {
    const cases: Query[] = [
      [['screen_hint', 'signup']],
      [
        ['iss', POPPY_ISSUER],
        ['target_link_uri', GOOD_TARGET],
        ['screen_hint', 'signup'],
      ],
      [
        ['target_link_uri', GOOD_TARGET],
        ['screen_hint', 'signup'],
      ],
      [
        ['iss', POPPY_ISSUER],
        ['target_link_uri', 'https://evil.example/'],
        ['target_link_uri', GOOD_TARGET],
        ['screen_hint', 'signup'],
      ],
    ];

    for (const query of cases) {
      expect(parse(query).authorizationParams).toStrictEqual({ screen_hint: 'signup' });
    }
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

  test('keeps the names of other parameters as they are, case included, and logs nothing for them', () => {
    const { authorizationParams } = parse([
      ['ISS', 'https://evil.example/'],
      ['Target_Link_Uri', 'https://evil.example/'],
    ]);

    expect(authorizationParams).toStrictEqual({
      ISS: 'https://evil.example/',
      Target_Link_Uri: 'https://evil.example/',
    });
    expectNoLogs();
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

  test('keeps a parameter named __proto__ as plain data when target_link_uri is ignored too', () => {
    const { authorizationParams } = parse([
      ['target_link_uri', 'https://evil.example/'],
      ['__proto__', 'polluted'],
    ]);

    expect(Object.getPrototypeOf(authorizationParams)).toBe(Object.prototype);
    expect(Object.keys(authorizationParams)).toStrictEqual(['__proto__']);
    expect({}).not.toHaveProperty('polluted');
    expectNoLogs();
  });
});

describe('poppy.parseLoginInitiation | the API', () => {
  test('answers at once, not with a promise', () => {
    expect(parse([])).not.toBeInstanceOf(Promise);
  });

  test('does not change the URL it is given when the iss is accepted', () => {
    const url = request([
      ['iss', POPPY_ISSUER],
      ['target_link_uri', GOOD_TARGET],
      ['foo', '1'],
    ]);
    const before = url.href;

    poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN });

    expect(url.href).toBe(before);
  });

  test('does not change the URL it is given when the iss is refused', () => {
    const url = request([
      ['iss', 'https://evil.example/'],
      ['target_link_uri', GOOD_TARGET],
      ['foo', '1'],
    ]);
    const before = url.href;

    expect(() => poppy.parseLoginInitiation(url, { appOrigin: APP_ORIGIN })).toThrow(IssuerValidationError);
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
