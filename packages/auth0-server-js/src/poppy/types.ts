import type { ActClaim } from '@auth0/auth0-auth-js';
import type { AbstractDataStore, AnonymousSessionData, TokenSet, UserClaims } from '../types.js';

// Types for Poppy (Personal Agent Protocol) in the web flow. The code was written against Poppy 0.3.
// Spec: https://personalagentprotocol.org/docs/0.3/spec

/**
 * Options for Poppy support, passed as `poppy` to the `ServerClient`. Without the `poppy` option nothing changes.
 *
 * Poppy is a draft protocol and this API is in beta, so both may change. The support was written against Poppy 0.3.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyOptions<TStoreOptions = unknown> {
  /**
   * The parsed `auth0-poppy.json` file. This package reads no files: your app, or its adapter, reads the file and
   * passes the object. The `ServerClient` takes a deep copy of the object when it is created, so changing the object
   * afterwards has no effect. The object must be plain data that can be copied, such as parsed JSON. A value that
   * cannot be copied, such as a function, makes the `ServerClient` constructor throw `InvalidConfigurationError`.
   */
  config: PoppyConfig;
  /**
   * Where guests are kept. A guest is an agent's browser that has joined a Poppy Session without signing in as a
   * user. It is never a user, so it is kept apart from the state store and the anonymous store.
   */
  guestStore: PoppyGuestStore<TStoreOptions>;
  /**
   * The longest an agent's session on your website lasts, in seconds. Default: `7200` (two hours). The session can
   * end sooner, when the agent's Poppy Session does.
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
 * The fields of `auth0-poppy.json` that this package reads, named as the file names them. The file has more fields,
 * and they are ignored here.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyConfig {
  /**
   * The Poppy version that the file was written for, as `major.minor`, such as `'0.3'`. The package checks only that
   * the value has this shape. It serves the value in `poppy.json` as it is, and does not check it against any version
   * it knows. The support was written against Poppy 0.3, and a newer version of the protocol can change names or add
   * members that this package does not know yet.
   */
  protocol_version: string;
  /** The organization that runs the website. `domain` is a lowercase host name with no scheme, port or path. */
  organization: { name: string; domain: string };
  /** The issuer of your Auth0 domain. It must match exactly, trailing slash included. */
  issuer: string;
  /** What each scope lets an agent do, keyed by scope name. */
  scopes?: Record<string, PoppyConfigScope>;
  /** The APIs of the website. */
  apis?: PoppyConfigApi[];
  /**
   * The website. `client_id` is the client of the web app. When it is set, it must be the `clientId` of the
   * `ServerClient`. `browser_session_endpoint` is the https URL where an agent's browser joins a Session.
   *
   * `unscoped` is `true` when the website does not apply the other scopes of the config, so that a signed-in browser
   * with `poppy:browser-sign-in` has the full access of the account there
   * ({@link https://personalagentprotocol.org/docs/0.4/spec#browser-join section 6 of Poppy 0.4}). Set it to
   * `true` for a website like that, because an agent reads it before it asks for the scope. The package serves it as
   * you wrote it, and serves nothing when you leave it out.
   */
  web: { client_id?: string; browser_session_endpoint: string; unscoped?: boolean };
}

/**
 * What a scope lets an agent do.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyConfigScope {
  description: string;
  /**
   * Hints about how much the scope allows. `changes` is `'none'`, `'reversible'` or `'irreversible'`; it is typed as
   * a `string` so that the config can be imported from a JSON file, and the `ServerClient` checks the value.
   */
  hints?: { changes: string; personal_data: boolean };
}

/**
 * An API of the website.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyConfigApi {
  /** The kind of API, such as `'openapi'` or `'mcp'`. */
  type: string;
  /** The https URL of the description of the API. */
  url: string;
  /** A short description that helps an agent choose the API. */
  description: string;
}

/**
 * The `act` claim of the ID token after an agent's browser join. `sub` is the agent's client id, which is the URL of
 * its client metadata document.
 *
 * The `poppy_*` members are Auth0's beta claims. The names may change, and `poppy_session_exp` may go away.
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
  /** When the Poppy Session ends, in Unix seconds. */
  poppy_session_exp?: number;
}

/**
 * The agent that drives a browser.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyAgent {
  /** The URL of the client metadata document of the agent. It identifies the agent. */
  cimdUrl: string;
  /** The id of the agent inside its Personal Agent, when the Personal Agent runs several agents. */
  poppyAgentId?: string;
}

/**
 * Whether the user has signed in for the Session: `'signed_out'` is a guest, and `'signed_in'` is a user whose
 * session has the agent in `act`.
 *
 * @beta
 * @category Poppy
 */
export type PoppySessionState = 'signed_out' | 'signed_in';

/**
 * A request that an agent's browser makes.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyAgentContext {
  kind: 'agent';
  state: PoppySessionState;
  /** The id of the Poppy Session. */
  sessionId: string;
  /** The id of the user, as the Personal Agent knows them at your website. */
  userId: string;
  agent: PoppyAgent;
  /**
   * An opaque key for this agent and this Session. It is the same key that `@auth0/auth0-api-js` gives for the
   * Session, so state kept by your website and by your API can share it.
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
 * - `'guest'`: a Poppy guest, which is an agent's browser that joined without signing in. Its `state` is
 *   `'signed_out'`. A guest is never a user: `getSession()` and `getUser()` do not return it. Use
 *   `poppy.getGuestAccessToken()` for the token.
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
 * What the guest store keeps for a guest.
 *
 * @beta
 * @category Poppy
 */
export interface PoppyGuestData {
  /** The `sub` of the guest. */
  sub: string;
  /** The Poppy Session of the guest. */
  poppy: { sessionId: string; userId: string; agent: PoppyAgent };
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
   * of the request, written as the URL parser writes it. It is left out when the request has no `target_link_uri` that
   * can be used.
   *
   * Use it whole. Do not keep only its path: a path that starts with two slashes, such as `//evil.example/x`, is read
   * as another site when it stands alone.
   */
  returnTo?: string;
  /**
   * Every other query parameter of the request, with one value each (the last). `iss` and `target_link_uri` are not in
   * it. The values come from the request of a browser, so they are not trusted. Which of them you pass on to the
   * authorize request is up to you.
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
 *   scopes of the config and, for a config of Poppy 0.4 or later, `poppy:browser-sign-in`.
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
