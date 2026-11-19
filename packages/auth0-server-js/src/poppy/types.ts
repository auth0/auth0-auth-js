import type { ActClaim } from '@auth0/auth0-auth-js';
import type { AbstractDataStore, AnonymousSessionData, TokenSet, UserClaims } from '../types.js';

// Types for Poppy (Personal Agent Protocol) in the web flow. The code is written against Poppy 1.0.
// Spec: https://personalagentprotocol.org/docs/1.0/spec

/**
 * Options for Poppy support, passed as `poppy` to the `ServerClient`. Without the `poppy` option nothing changes.
 *
 * The code is written against Poppy 1.0. This API is in beta, so its names may still change.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyOptions<TStoreOptions = unknown> {
  /**
   * The parsed `poppy.json` file that `auth0 poppy config` writes. Pass it as it is. This package reads no files: your
   * app, or its adapter, reads the file and passes the object. The `ServerClient` takes a deep copy of the object when
   * it is created, so changing the object afterwards has no effect, and it serves that copy at
   * `/.well-known/poppy.json`. The object must be plain data that can be copied, such as parsed JSON. A value that
   * cannot be copied, such as a function, makes the `ServerClient` constructor throw `InvalidConfigurationError`.
   */
  config: PoppyConfig;
  /**
   * Where guests are kept. A guest is an agent's browser that has joined a Poppy Session without signing in as a
   * user. It is never a user, so it is kept apart from the state store and the anonymous store.
   */
  guestStore: PoppyGuestStore<TStoreOptions>;
  /**
   * The longest an agent's session on your website lasts, in seconds. A whole number above 30, because a session ends 30
   * seconds before its deadline. Default: `7200` (two hours). The session can end sooner because of the `exp` or the
   * `session_expiry` of the ID token. A value above 7200 has no effect with Auth0 today, because Auth0 gives the ID
   * token at most two hours. A guest that renews its access token, from a silent login or once the token has expired, keeps the creation time and the deadline of its first join (the deadline can only get earlier). The SDK
   * does not see the end of the agent's Poppy Session, so it does not end the session then.
   */
  agentSessionMaxAge?: number;
  /**
   * Your own values for the `oauth-protected-resource` document (RFC 9728) that your website serves. A member given
   * here is served as it is. A member left out is inferred from the config. The `ServerClient` takes a deep copy of
   * the object when it is created, so changing the object afterwards has no effect.
   *
   * A `resource` or an `authorization_servers` that agents would reject is still served, and `poppy.verifyConfig()`
   * reports it.
   */
  protectedResource?: PoppyProtectedResource;
}

/**
 * The metadata of a protected resource, as in {@link https://www.rfc-editor.org/rfc/rfc9728 RFC 9728}. A member given
 * here is served as it is, and a member left out is inferred from the config.
 *
 * The members must be plain data that can be served as JSON. The `ServerClient` copies the object with
 * `structuredClone` when it is created, so a change to the object, or to anything inside it, afterwards does not reach
 * the copy. A member that cannot be copied, such as a function, makes the `ServerClient` constructor throw.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyProtectedResource {
  /** The resource identifier. */
  resource?: string;
  /** The issuers of the authorization servers that can be used with the resource. */
  authorization_servers?: string[];
  /** Other RFC 9728 members, such as `scopes_supported`. They are served as they are. */
  [member: string]: unknown;
}

/**
 * The `poppy.json` file that the Auth0 CLI writes with `auth0 poppy config`, as the CLI writes it. Pass the parsed file
 * as it is. This package serves it at `/.well-known/poppy.json` as a copy that is made when the `ServerClient` is
 * created, so the file is the one source of what your website tells agents.
 *
 * Only the members that this package reads are typed. Every other member is kept and served as written, so a member
 * that a later version of the protocol or of the CLI adds needs no change here. The type has index signatures, so an
 * imported JSON file type-checks without a cast.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyConfig {
  /**
   * The organization that runs the website. `domain` is the host that serves `poppy.json`: a lowercase host name with
   * no scheme, path or trailing dot, and with its port when the port is not 443 (for example `localhost:3000` or
   * `shop.example:8443`). The protected resource of the website is `https://` and this value.
   */
  organization: {
    domain: string;
    [member: string]: unknown;
  };
  /**
   * The Auth0 side of the file. `issuer` is the issuer of your Auth0 domain. It must match exactly, trailing slash
   * included. `scopes`, when it is an object, names the scopes that `poppy.verifyConfig()` looks for in the metadata of
   * Auth0, by its keys.
   */
  auth: {
    issuer: string;
    [member: string]: unknown;
  };
  /** Every other member of the file, such as `protocol_version`, `apis` or `web`. It is served as written. */
  [member: string]: unknown;
}

/**
 * The `act` claim of the ID token after an agent's browser join. `sub` is the agent: the URL of its client metadata
 * document, or the ID of its Auth0 agent when it is linked to one.
 *
 * The `poppy_*` members are Auth0's beta claims. The names may change.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyActClaim extends ActClaim {
  /** The id of the Poppy Session. */
  poppy_sid?: string;
  /** The id of the user, as the Personal Agent knows them at your website. It is opaque. */
  poppy_user_id?: string;
  /** The id of the agent that the Session is for, when the Personal Agent runs several agents. */
  poppy_agent_id?: string;
}

/**
 * Whether the user has signed in for the Session: `'guest'` is an agent's browser that joined without signing in as a
 * user, and `'signed_in'` is a user whose session has the agent in `act`.
 *
 * @beta
 * @category Poppy
 */
export type PoppySessionState = 'guest' | 'signed_in';

/**
 * A request that an agent's browser makes.
 *
 * `sub`, `sub_profile` and `act` are the claims of the ID token of the join. They keep the names that the token gives
 * them, and `act` is kept whole, as Auth0 sent it.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyAgentContext {
  kind: 'agent';
  state: PoppySessionState;
  /** The `sub` of the ID token: the guest, or the user. */
  sub: string;
  /** The `sub_profile` of the ID token, when it has one and it is a string. */
  sub_profile?: string;
  /**
   * The `act` claim of the ID token, whole and as Auth0 sent it, with the members that this package does not know.
   * `act.sub` is the agent. It is the URL of the client metadata document of the agent, unless the agent is linked to an
   * Auth0 agent: then it is the ID of that agent, and not a URL. The Session is named by `act.poppy_sid` and
   * `act.poppy_user_id`, and `act.poppy_agent_id` names the agent inside its Personal Agent. The object is a copy: a
   * change to it reaches no store. `poppy_sid` and `poppy_user_id` are always there: a context is built only from a
   * login that has both.
   */
  act: PoppyActClaim & { poppy_sid: string; poppy_user_id: string };
  /**
   * The scopes of the access token of the join. It is empty for a guest. For a signed-in agent it is the `scope` of
   * the access token of the join, split on spaces.
   */
  scopes: string[];
  /**
   * An opaque key for this agent, this Session and this User. It is built with the same formula as the key that
   * `@auth0/auth0-api-js` gives for the Session (once its Poppy support is released), so state kept by your website and
   * by your API can share it, with one exception: when the agent is linked to an Auth0 agent, `act.sub` is the ID of
   * that agent here, and the API gets the URL of the agent from the `Poppy-Session` header, so the two keys differ.
   */
  key: string;
}

/**
 * Who makes a request: a person (`'human'`) or an agent's browser (`'agent'`).
 *
 * @beta
 * @category Poppy
 */
export type PoppyContext = { kind: 'human' } | PoppyAgentContext;

/**
 * Who is behind a request, for a website that uses anonymous sessions and Poppy. It is what `poppy.getVisitor()` gives.
 * Each `kind` has its own read and its own token method, and `getVisitor()` puts them in one result:
 * - `'none'`: nobody. There is no guest, no user session and no anonymous session.
 * - `'anonymous'`: a regular anonymous session, as `anonymous.getSession()` gives it. Use `anonymous.getAccessToken()`
 *   for the token.
 * - `'user'`: a user session. When an agent joined the session, `poppy` is there too, and its `state` is `'signed_in'`.
 *   Use `getAccessToken()` of the `ServerClient` for the token.
 * - `'guest'`: a Poppy guest, which is an agent's browser that joined without signing in. Its `state` is `'guest'`. A
 *   guest is never a user: `getSession()` and `getUser()` do not return it. Use `poppy.getGuestAccessToken()` for the
 *   token.
 *
 * Handle every `kind` in one `switch`. If you end the `switch` with a `never` check in `default`, the build of your
 * app stops when a later version adds a `kind` that your app does not handle.
 *
 * @beta
 * @category Poppy
 */
export type PoppyVisitor =
  | { kind: 'none' }
  | { kind: 'anonymous'; anonymous: AnonymousSessionData }
  | { kind: 'user'; user: UserClaims; poppy?: PoppyAgentContext }
  | { kind: 'guest'; poppy: PoppyAgentContext };

/**
 * What the guest store keeps for a guest. `sub`, `sub_profile` and `act` are the claims of the ID token of the join, with
 * the names that the token gives them.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyGuestData {
  /** The `sub` of the guest. */
  sub: string;
  /** The `sub_profile` of the guest, when the ID token has one and it is a string. */
  sub_profile?: string;
  /** The `act` claim of the ID token, whole and as Auth0 sent it. The agent is `act.sub`. */
  act: PoppyActClaim;
  /** The access token of the join. It is never refreshed. */
  tokenSets: TokenSet[];
  /** When the guest was created, in Unix seconds. */
  createdAt: number;
  /** The deadline of the guest, in Unix seconds. After it the guest is gone. */
  expiresAt: number;
  // Needed because the bound of `AbstractStore` is a JWT payload.
  [key: string]: unknown;
}

/**
 * Store for guests.
 *
 * Separate from the state store on purpose: a guest is not a user. Writing one into the state store would make
 * `getSession()` and `getUser()` return something for a visitor who has not signed in.
 *
 * @beta
 * @category Poppy
 */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface PoppyGuestStore<TStoreOptions = unknown> extends AbstractDataStore<PoppyGuestData, TStoreOptions> {}

/**
 * Options for `poppy.parseLoginInitiation()`.
 *
 * @beta
 * @category Poppy
 */
export interface ParseLoginInitiationOptions {
  /**
   * The public origin of your website, such as `https://zepto.example`. A `target_link_uri` is used as the landing page
   * only when it is on this origin: the same scheme, host and port. Only the origin counts, so a path, a query or a
   * fragment in this value is ignored.
   *
   * It must be an absolute `https:` or `http:` URL. A value that is not an absolute URL makes `parseLoginInitiation()`
   * throw a `TypeError`. Write the scheme: `localhost:3000` is read as a URL with the scheme `localhost:`, and no
   * landing page is on its origin.
   */
  appOrigin: string;
}

/**
 * What the login route needs from the query of a request to it.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyLoginInitiation {
  /**
   * The page to land on after the login, as an absolute URL on the origin of your website. It is the `target_link_uri`
   * of the request, written as the URL parser writes it. It is left out when the request has no `iss` that is the
   * issuer of your config, or no `target_link_uri` that can be used.
   *
   * Use it whole. Do not keep only its path: a path that starts with two slashes, such as `//evil.example/x`, is read
   * as another site when it stands alone.
   */
  returnTo?: string;
  /**
   * Every other query parameter of the request, with one value each (the last). `iss` and `target_link_uri` are not in
   * it. The values come from the request of a browser, so they are not trusted. Which of them you pass on to the
   * authorize request is up to you.
   *
   * Pass on only the names you expect, such as `login_hint` or `ui_locales`, and never the whole object. Any visitor
   * can put `redirect_uri`, `audience`, `scope`, `prompt`, `max_age`, `organization` or `connection` in the query, and
   * the options of `startInteractiveLogin()` would take them as yours.
   */
  authorizationParams: Record<string, string>;
}

/**
 * A discovery document for your website to send, as `poppy.getDiscoveryDocument()` gives it.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyDiscoveryDocument {
  /** The HTTP status to send. It is always `200`. */
  status: number;
  /** The HTTP headers to send. */
  headers: Record<string, string>;
  /** The text to send as the body. It is JSON. */
  body: string;
}

/**
 * What a problem that `poppy.verifyConfig()` finds is about:
 * - `'metadata_unavailable'`: the metadata of Auth0 could not be read, so only the checks that need no request were
 *   made.
 * - `'protected_resource_missing'`: the `protected_resources` of the metadata does not list the resource of your
 *   website.
 * - `'scopes_not_supported'`: the `scopes_supported` of the metadata does not list some scopes that agents request: the
 *   scopes of the config and `poppy:browser-sign-in`.
 * - `'protected_resource_override_mismatch'`: a value of the `protectedResource` option is not one that agents accept.
 *
 * @beta
 * @category Poppy
 */
export type PoppyConfigIssueCode =
  | 'metadata_unavailable'
  | 'protected_resource_missing'
  | 'scopes_not_supported'
  | 'protected_resource_override_mismatch';

/**
 * A problem that `poppy.verifyConfig()` found between the config and Auth0.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyConfigIssue {
  code: PoppyConfigIssueCode;
  /**
   * A fixed text for a log. It says what is wrong and why agents care. It may name a scope or the resource of the
   * config, and it never holds a value from a request, a token, the metadata of Auth0 or the `protectedResource`
   * option.
   */
  message: string;
}
