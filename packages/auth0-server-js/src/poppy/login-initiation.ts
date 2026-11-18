import { LOGIN_INITIATION_PARAMS } from './constants.js';
import type { ParseLoginInitiationOptions, PoppyLoginInitiation } from './types.js';

// The checks on the query of a request to the login route (OpenID Connect third-party initiated login). `iss` and
// `target_link_uri` are both optional. Anyone can send a browser to the login route with any query, so nothing in the
// query is trusted. A request is never refused: a login link that carries an `iss` that is not the issuer of this app
// is a link that Auth0 did not make for this app, so `iss` and `target_link_uri` are ignored and the login goes on.

// The URL to land on, or `undefined` when `value` cannot be used. A value can be used when it is an absolute URL of a
// web page on the origin of the website. The checks run on the URL as the parser reads it, as a browser does, because a
// check on the text would not see that `https://zepto.example@evil.example/` is another site.
function landingPage(value: string, appOrigin: string): string | undefined {
  let target: URL;

  try {
    // There is no base URL, so a path such as `/cart` and a scheme-relative URL such as `//evil.example/` do not parse.
    target = new URL(value);
  } catch {
    return undefined;
  }

  // The scheme is checked as well as the origin, because the origin of some URLs is not their own. The origin of
  // `blob:https://zepto.example/x` is `https://zepto.example`. The origin of `javascript:` and `data:` URLs is `null`,
  // and so is the origin of an `appOrigin` that has no web scheme, such as `localhost:3000`. `null` equals `null` as
  // text, so without this check a script URL would match such an `appOrigin`.
  const isWebPage = target.protocol === 'https:' || target.protocol === 'http:';
  // A landing page has no use for a user name or a password, so a URL that has one is not used.
  const hasCredentials = target.username !== '' || target.password !== '';

  if (!isWebPage || hasCredentials || target.origin !== appOrigin) {
    return undefined;
  }

  // The text of the parser, not the text of the request. What the app redirects to is then what was checked here, with
  // no tab, line break, backslash or dot segment left in it.
  return target.href;
}

/**
 * @internal
 * Checks the query of a request to the login route, and returns what the route needs from it.
 * It does not throw for the query, whatever it holds, and it logs nothing: anyone can send a browser to the login route
 * with any query, so a log line for it would be one that anyone can write.
 * See `ServerPoppyClient.parseLoginInitiation` for the rules.
 *
 * @param url The URL of the login request.
 * @param options The origin of the website. It is read on every call, so a wrong one fails on every request.
 * @param issuer The `auth.issuer` of the config.
 */
export function readLoginInitiation(
  url: URL,
  options: ParseLoginInitiationOptions,
  issuer: string
): PoppyLoginInitiation {
  const appOrigin = new URL(options.appOrigin).origin;
  const { searchParams } = url;
  const { issuer: issuerName, targetLinkUri: targetName } = LOGIN_INITIATION_PARAMS;

  // `target_link_uri` is read only when `iss` is there, once, and is the issuer: it is then a link that Auth0 made for
  // this app. Without `iss` there is nothing that says so, so it is ignored. When `iss` is there and cannot be used, it is
  // ignored too, and the login goes on as a normal login. An empty value is a value, so it does not match. A repeated
  // `iss` does not match even when the values are equal: a parser that takes the first value and one that takes the last
  // would read the request in two ways.
  const [iss, ...moreIss] = searchParams.getAll(issuerName);
  const issIsIssuer = iss === issuer && moreIss.length === 0;

  // A `target_link_uri` that is repeated is ignored, because there is no way to tell which value is meant.
  const [target, ...moreTargets] = issIsIssuer ? searchParams.getAll(targetName) : [];
  const returnTo = target !== undefined && moreTargets.length === 0 ? landingPage(target, appOrigin) : undefined;

  // `Object.fromEntries` makes a name such as `__proto__` an ordinary property, and a later value replaces an earlier
  // one.
  const authorizationParams = Object.fromEntries(
    [...searchParams].filter(([name]) => name !== issuerName && name !== targetName)
  );

  return returnTo === undefined ? { authorizationParams } : { returnTo, authorizationParams };
}
