import type { AuthClient } from '@auth0/auth0-auth-js';
import { errors } from 'jose';
import { InvalidPoppySessionError } from '../errors.js';
import { isSessionExpiryReached } from '../state/utils.js';
import type { AnonymousSessionData, SessionData, TokenSet } from '../types.js';
import { readAgentLogin } from './claims.js';
import type { AgentLogin } from './claims.js';
import {
  buildDiscoveryDocuments,
  findConfigIssues,
  findOverrideIssues,
  metadataUnavailableIssue,
} from './discovery.js';
import { readLoginInitiation } from './login-initiation.js';
import { computePoppySessionKey } from './session-key.js';
import type {
  ParseLoginInitiationOptions,
  PoppyAgent,
  PoppyAgentContext,
  PoppyConfig,
  PoppyConfigIssue,
  PoppyContext,
  PoppyDiscoveryDocument,
  PoppyGuestData,
  PoppyGuestStore,
  PoppyLoginInitiation,
  PoppyProtectedResource,
  PoppySessionState,
  PoppyVisitor,
} from './types.js';

/**
 * @internal
 * Options for constructing a ServerPoppyClient.
 *
 * Poppy needs one issuer, so unlike the passkey client this client has no domain resolver: it receives what the
 * parent client already knows about the one Auth0 domain.
 */
export interface ServerPoppyClientOptions<TStoreOptions> {
  config: PoppyConfig;
  protectedResource?: PoppyProtectedResource;
  guestStore: PoppyGuestStore<TStoreOptions>;
  guestStoreIdentifier: string;
  getSession: (storeOptions?: TStoreOptions) => Promise<SessionData | undefined>;
  /**
   * Reads the regular anonymous session. The parent client gives it only when it has an anonymous store, because its
   * `anonymous` getter throws without one.
   */
  getAnonymousSession?: (storeOptions?: TStoreOptions) => Promise<AnonymousSessionData | undefined>;
  getServerMetadata: () => ReturnType<AuthClient['getServerMetadata']>;
}

// What the parent client reads from Auth0 when it is asked for the metadata.
type ServerMetadata = Awaited<ReturnType<AuthClient['getServerMetadata']>>;

// The visitors that the guest store and the state store can show. The anonymous store is for `getVisitor()` alone.
type SessionVisitor = Exclude<PoppyVisitor, { kind: 'anonymous' }>;

// The context of an agent's browser. The Session key is made here, so every context has the one that the API SDK gives
// for the same Session.
async function agentContext(
  state: PoppySessionState,
  session: { sessionId: string; userId: string; agent: PoppyAgent }
): Promise<PoppyAgentContext> {
  const { sessionId, userId } = session;
  const { cimdUrl, poppyAgentId } = session.agent;

  return {
    kind: 'agent',
    state,
    sessionId,
    userId,
    // A new object with the members of the agent and no others. A change by the app never reaches a store, and a record
    // from a custom store cannot add members to what the app sees.
    agent: typeof poppyAgentId === 'string' ? { cimdUrl, poppyAgentId } : { cimdUrl },
    key: await computePoppySessionKey(cimdUrl, sessionId),
  };
}

// Whether a record from the guest store has the members that a read uses. The SDK always writes them, but a custom
// guest store can give back anything, and a record that lacks one is not trusted. `expiresAt` must be a finite number:
// the check of the deadline is false for `NaN`, so a guest with that deadline would never end.
function hasGuestMembers(guest: PoppyGuestData): boolean {
  const { expiresAt, poppy } = guest;

  return (
    Number.isFinite(expiresAt) &&
    typeof poppy?.sessionId === 'string' &&
    typeof poppy.userId === 'string' &&
    typeof poppy.agent?.cimdUrl === 'string'
  );
}

// The agent in a stored session. A session from before the `poppy` option, or from a login that did not go through the
// Poppy path, keeps the `act` as the token had it, and that `act` can hold a Poppy Session that is not well formed. It is
// a person's session then, and reading it must not fail.
function agentLoginOf(session: SessionData | undefined): AgentLogin | undefined {
  try {
    return readAgentLogin(session?.user);
  } catch (error) {
    if (error instanceof InvalidPoppySessionError) {
      return undefined;
    }

    throw error;
  }
}

/**
 * Client for Poppy (Personal Agent Protocol) on the server. Reach it through `serverClient.poppy`, which needs the
 * `poppy` option on the `ServerClient`.
 *
 * @beta
 * @category Sub-clients
 */
export class ServerPoppyClient<TStoreOptions = unknown> {
  readonly #options: ServerPoppyClientOptions<TStoreOptions>;
  readonly #documents: Map<string, PoppyDiscoveryDocument>;

  /**
   * @internal
   */
  constructor(options: ServerPoppyClientOptions<TStoreOptions>) {
    this.#options = options;
    // The bodies are built here, once, as text. A change to the config, or to the object of the `protectedResource`
    // option, after this point cannot change what the website serves.
    this.#documents = buildDiscoveryDocuments(options.config, options.protectedResource);
  }

  /**
   * Gives the document to send for a request path, or `undefined` when the path is not one that Poppy uses.
   *
   * A website that supports Poppy publishes two JSON files on its own domain. This package serves no files: your
   * framework adapter mounts both paths and sends what this method returns. Mount them outside any session handling.
   * - `/.well-known/poppy.json` is built from the config
   *   ({@link https://personalagentprotocol.org/docs/0.3/spec#discovery section 3 of the specification}).
   * - `/.well-known/oauth-protected-resource` names the resource, which is `https://` and the `organization.domain` of
   *   the config, and the issuer of the config as its authorization server
   *   ({@link https://personalagentprotocol.org/docs/0.3/spec#oauth-server section 3.2},
   *   {@link https://www.rfc-editor.org/rfc/rfc9728 RFC 9728}). With the `protectedResource` option you give your own
   *   values: a value you give is served as it is, and a value you leave out is inferred. Other members you give follow
   *   the two above, in the order you wrote them. `poppy.json` does not depend on this option.
   *
   * Pass the path of the request without its query. A path with a query, such as `/.well-known/poppy.json?x=1`, gives
   * `undefined`, as does any other path.
   *
   * The documents are built once, when the `ServerClient` is created. The status is always `200`. Every call returns a
   * new object with its own headers, so a change to the result does not reach the next call. A `protectedResource` that
   * agents would reject is still served: `verifyConfig()` reports it.
   *
   * @param path The path of the request, such as `/.well-known/poppy.json`.
   *
   * @returns The status, the headers and the body to send, or `undefined`.
   *
   * @beta
   */
  getDiscoveryDocument(path: string): PoppyDiscoveryDocument | undefined {
    const document = this.#documents.get(path);

    return document && { status: document.status, headers: { ...document.headers }, body: document.body };
  }

  /**
   * Compares the config with the metadata of Auth0 the way an agent does, and returns the problems it finds. An agent
   * that finds a mismatch in the resource or in the issuer does not use the files of the website, and it does not say
   * so. Call this once when the website starts, and log what it returns. The result is `[]` when there is nothing to
   * report.
   *
   * The issues, in this order:
   * - `protected_resource_override_mismatch`: a value of the `protectedResource` option that agents reject. The
   *   `resource` must be exactly `https://` and the `organization.domain` of the config, and `authorization_servers`
   *   must list the `issuer` of the config exactly as it is written there. A value that is inferred always passes. This
   *   check needs no request.
   * - `protected_resource_missing`: the `protected_resources` of the metadata does not list the resource of your
   *   website. The match ignores case and nothing else: a path, a port or a trailing slash is another entry
   *   ({@link https://personalagentprotocol.org/docs/0.3/spec#oauth-server section 3.2}).
   * - `scopes_not_supported`: the `scopes_supported` of the metadata does not list some scopes that agents request. The
   *   message names them. These are the scopes of the config and, when the `protocol_version` of the config is 0.4 or
   *   later, `poppy:browser-sign-in`, which a website that offers a browser join has to support. The specification asks
   *   the issuer to list every scope that an agent can request
   *   ({@link https://personalagentprotocol.org/docs/0.3/spec#scopes section 4.7}).
   * - `metadata_unavailable`: the metadata could not be read, so the two checks above that need it were not made. This
   *   method does not reject for that.
   *
   * The issuer is not compared: the `ServerClient` requires the `issuer` of the config to match its `domain` when it is
   * created. The `message` of an issue is a fixed text. It may name a scope or the resource of the config, and it never
   * holds a value from a request, a token, the metadata or the `protectedResource` option.
   *
   * @returns The issues found, which can be empty.
   *
   * @beta
   */
  async verifyConfig(): Promise<PoppyConfigIssue[]> {
    const { config, protectedResource } = this.#options;
    // These need no request, so they are reported even when the metadata cannot be read.
    const overrideIssues = findOverrideIssues(config, protectedResource);
    let metadata: ServerMetadata;

    // Only the read is inside the `try`, so a bug in the checks cannot pass for an unavailable metadata.
    try {
      metadata = await this.#options.getServerMetadata();
    } catch {
      return [...overrideIssues, metadataUnavailableIssue()];
    }

    return [...overrideIssues, ...findConfigIssues(config, metadata)];
  }

  /**
   * Tells who makes the request: a person (`{ kind: 'human' }`) or an agent's browser (`kind: 'agent'`).
   *
   * An agent's browser is in one of two states, and `state` says which:
   * - `'signed_out'`: a guest. The browser joined a Poppy Session without signing in as a user. The guest is kept in
   *   the guest store and never in the state store, so `getSession()` and `getUser()` do not return it.
   * - `'signed_in'`: a user whose session has the agent in `act`.
   *
   * A guest comes first: when the browser has a guest and a session, the context is the guest's.
   *
   * A guest, and the session of a signed-in agent, have a deadline that nothing extends. They end 30 seconds before
   * it, as any session with a `session_expiry` does. The SDK does not see a sign-out or a disconnect on Auth0's side,
   * so it does not end them earlier. A guest that has ended is deleted from the guest store and read as no guest.
   *
   * @param storeOptions Optional options passed to the guest store and the state store.
   *
   * @throws The error of the guest store or of the state store, when one of them fails.
   *
   * @returns The context of the request.
   *
   * @beta
   */
  async getContext(storeOptions?: TStoreOptions): Promise<PoppyContext> {
    const visitor = await this.#readSessionVisitor(storeOptions);

    // A guest has a `poppy`, and so has a user whose session holds an agent. Anyone else is a person.
    return visitor.kind !== 'none' && visitor.poppy ? visitor.poppy : { kind: 'human' };
  }

  /**
   * Tells who is behind the request, for a website that uses anonymous sessions and Poppy. A request can come from a
   * signed-in user, a regular anonymous visitor, a Poppy guest, a signed-in agent or nobody, and each has its own read,
   * its own token method and its own key. This method reads them in one safe order and returns one result, so a single
   * `switch` on `kind` handles every case and the guest cannot be forgotten.
   *
   * The order is part of the contract. The first step that finds a visitor decides, and nothing is read after it:
   * 1. A guest: `{ kind: 'guest', poppy }`, and `poppy.state` is `'signed_out'`.
   * 2. A user session: `{ kind: 'user', user }`. When an agent joined the session, `poppy` is there too, and its `state`
   *    is `'signed_in'`. A session with no `user` is skipped. An `act` claim that is not a well-formed Poppy Session
   *    gives a plain user, as in `getContext()`.
   * 3. A regular anonymous session: `{ kind: 'anonymous', anonymous }`, as `anonymous.getSession()` gives it. This step
   *    is made only when the `ServerClient` has an `anonymousStore`.
   * 4. Otherwise `{ kind: 'none' }`.
   *
   * A guest comes first because the browser is then driven by an agent that has not signed in. The same browser can
   * hold a user session that is not the agent's, such as the earlier login of a person, and the agent must not act as
   * that user. The user session stays where it is: `getSession()` and `getUser()` still return it, and they never
   * return a guest.
   *
   * A guest, and the session of a signed-in agent, end 30 seconds before their deadline. One that has ended is read as
   * absent, as in `getContext()`, and the next step is made.
   *
   * The method writes nothing and sends no request to Auth0. It only deletes a guest or a session that has ended. Each
   * store is read at most once per call.
   *
   * @param storeOptions Optional options passed to the guest store, the state store and the anonymous store.
   *
   * @throws The error of a store, when one of them fails. A store that fails is never read as empty, so a guest is not
   * taken for a user or for an anonymous visitor, and the stores after it are not read.
   *
   * @returns The visitor.
   *
   * @beta
   */
  async getVisitor(storeOptions?: TStoreOptions): Promise<PoppyVisitor> {
    const visitor = await this.#readSessionVisitor(storeOptions);
    const { getAnonymousSession } = this.#options;

    if (visitor.kind !== 'none' || !getAnonymousSession) {
      return visitor;
    }

    const anonymous = await getAnonymousSession(storeOptions);

    return anonymous ? { kind: 'anonymous', anonymous } : visitor;
  }

  /**
   * Returns the access token of a guest, or `undefined` when there is none to use. The token is the one that Auth0
   * issued when the browser joined. It is never refreshed, and this method never sends a request to Auth0.
   *
   * It is `undefined` when the browser has no guest, when the guest has ended, and from the second the token expires.
   * The guest can last longer than the token. For a signed-in agent, use `getAccessToken()` of the `ServerClient`.
   *
   * @param storeOptions Optional options passed to the guest store.
   *
   * @throws The error of the guest store, when it fails.
   *
   * @returns The token set of the guest, or `undefined`.
   *
   * @beta
   */
  async getGuestAccessToken(storeOptions?: TStoreOptions): Promise<TokenSet | undefined> {
    const tokenSet = (await this.#readGuest(storeOptions))?.tokenSets?.[0];

    // The same test as `getAccessToken()`: the token is good until its `expiresAt`. A value that is not a number fails it.
    if (!tokenSet || !(tokenSet.expiresAt > Date.now() / 1000)) {
      return undefined;
    }

    const { audience, accessToken, scope, expiresAt } = tokenSet;

    return { audience, accessToken, scope, expiresAt };
  }

  /**
   * Checks the query of a request to your login route, and gives back what the route needs from it. Call it first,
   * before you start the login.
   *
   * The query may carry `iss` and `target_link_uri`, the parameters of a third-party initiated login
   * ({@link https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin OpenID Connect Core 1.0, section 4}).
   * Both are optional, and each one is checked when it is there. Anyone can send a browser to your login route with
   * any query, so nothing in it is trusted:
   * - When the request has `iss`, it must appear once and be the `issuer` of your config, character for character. An
   *   empty value, another case, a missing trailing slash and a repeated `iss` are all refused.
   * - When the request has `target_link_uri`, it becomes `returnTo` only when it appears once, it is an absolute
   *   `https:` or `http:` URL with no user name or password, and it is on the origin of `appOrigin`. In every other
   *   case there is no `returnTo` and no error: use your default landing page. This keeps your login route from being
   *   an open redirect.
   * - `authorizationParams` has every other query parameter, with one value each (the last). It never has `iss` or
   *   `target_link_uri`.
   *
   * The method reads no request, file or environment. It does not start the login and sends nothing.
   *
   * @param url The URL of the login request, with its query.
   * @param options The origin of your website.
   *
   * @throws {IssuerValidationError} When the request has an `iss` that is empty, repeated, or not the issuer of the
   * config.
   * @throws {TypeError} When `appOrigin` is not an absolute URL.
   *
   * @returns The page to land on, if there is one, and the other query parameters.
   *
   * @beta
   */
  parseLoginInitiation(url: URL, options: ParseLoginInitiationOptions): PoppyLoginInitiation {
    return readLoginInitiation(url, options, this.#options.config.issuer);
  }

  /**
   * The read that `getContext()` and `getVisitor()` share, so the two always agree and each store is read once. The
   * guest comes first, and when there is one nothing else is read. Then comes the user session, which `getSession()`
   * reads: it enforces the deadline of the session and deletes a session that has ended. A session with no `user` is not
   * a visitor. An `act` that is not a well-formed Poppy Session gives a plain user, never an error. The anonymous store
   * is not read here, because `getContext()` has no use for it.
   */
  async #readSessionVisitor(storeOptions?: TStoreOptions): Promise<SessionVisitor> {
    const guest = await this.#readGuest(storeOptions);

    if (guest) {
      return { kind: 'guest', poppy: await agentContext('signed_out', guest.poppy) };
    }

    const session = await this.#options.getSession(storeOptions);
    const user = session?.user;

    if (!user) {
      return { kind: 'none' };
    }

    const login = agentLoginOf(session);

    // `poppy` is left out for a plain user, not set to `undefined`, so the visitor has no key with that value.
    return login ? { kind: 'user', user, poppy: await agentContext('signed_in', login) } : { kind: 'user', user };
  }

  /**
   * Reads the guest of the browser, for the read of the visitor and for `getGuestAccessToken()`. The guest store does
   * not check `expiresAt`: it gives the record back until the encrypted value ends, and 15 seconds after that, and then
   * it throws `JWTExpired`. A guest must never outlive its deadline, so the checks are made here:
   * - `JWTExpired` means the guest has ended. It is deleted, and there is no guest.
   * - A record that lacks a member that a read uses is deleted, and there is no guest.
   * - A guest whose `expiresAt` is 30 seconds away or less is deleted, and there is no guest.
   * - Any other error of the store goes to the caller. The guest is not deleted, and the visitor is not read as a person.
   *
   * The delete is best-effort (see `#discardGuest`). The read of the guest is not: a store that fails is never read as
   * empty.
   */
  async #readGuest(storeOptions?: TStoreOptions): Promise<PoppyGuestData | undefined> {
    const { guestStore, guestStoreIdentifier } = this.#options;
    let guest: PoppyGuestData | undefined;

    try {
      guest = await guestStore.get(guestStoreIdentifier, storeOptions);
    } catch (error) {
      if (error instanceof errors.JWTExpired) {
        await this.#discardGuest(storeOptions);
        return undefined;
      }

      throw error;
    }

    if (!guest) {
      return undefined;
    }

    // `isSessionExpiryReached` is true when `expiresAt` is 30 seconds away or less. The deadline is a number, never a
    // truthy value: one that is 0 is a time in the past.
    if (!hasGuestMembers(guest) || isSessionExpiryReached(guest.expiresAt)) {
      await this.#discardGuest(storeOptions);
      return undefined;
    }

    return guest;
  }

  /**
   * Deletes a guest that has ended or is not valid, swallowing store failures.
   *
   * The guest is already read as absent, so the outcome the caller cares about is settled: a guest store that fails to
   * delete (a custom store whose backend is down) must not turn the read into an error. A guest that stays behind
   * cannot outlive its deadline, because every read of it checks that.
   */
  async #discardGuest(storeOptions?: TStoreOptions): Promise<void> {
    try {
      await this.#options.guestStore.delete(this.#options.guestStoreIdentifier, storeOptions);
    } catch {
      // best-effort: the cleanup must not make the read fail
    }
  }
}
