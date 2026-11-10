import { InvalidConfigurationError, InvalidRequestError } from '../errors.js';
import type {
  PoppySession,
  VerifiedAccessTokenClaims,
  VerifiedPoppyRequest,
  VerifyAccessTokenOptions,
  VerifyPoppyRequestOptions,
} from '../types.js';
import type { AgentMetadataFetcher } from './agent-metadata.js';
import {
  AUTHORIZATION_MALFORMED_MESSAGE,
  DEFAULT_AGENT_CLIENT_ID_CLAIMS,
  REGISTERED_AGENT_NEEDS_SESSION_MESSAGE,
} from './constants.js';
import type { DelegationVerifier } from './delegation.js';
import { InvalidSessionError } from './errors.js';
import type { ResolvedPoppyOptions } from './options.js';
import { readPoppyRequestHeaders, type PoppyRequestHeaders } from './request-headers.js';
import { isGuestToken, sessionFromToken } from './session-from-token.js';
import { parseSessionJwt } from './session-jwt.js';
import { checkSessionRecord } from './session-record.js';
import {
  checkSessionClaims,
  computeAth,
  computeSessionKey,
  expectedRequestUrl,
  verifySessionSignature,
} from './session-verifier.js';

// The pipeline behind `ApiClient.verifyPoppyRequest`, whose JSDoc lists the checks and their order. It holds no state:
// the client builds the fetcher and the delegation verifier once and passes them in, so their caches live as long as
// the client does. Spec: https://personalagentprotocol.org/docs/0.3/spec, section 5.3.

/**
 * What the pipeline needs from the client that runs it.
 */
export interface PoppyPipeline {
  /** The `poppy` options of the client, checked and resolved. */
  options: ResolvedPoppyOptions;

  /** Fetches and caches the client metadata and the keys of the agents. The delegation verifier uses it. */
  fetcher: AgentMetadataFetcher;

  /** Verifies delegations, and keeps the ones it verified until they expire. */
  delegations: DelegationVerifier;

  /**
   * Whether the `domains` option of the client is a function. `verifyAccessToken` passes such a function the URL of the
   * request, so the pipeline works that URL out for a token request even when the token has no DPoP proof to check.
   */
  hasDomainsResolver: boolean;

  /**
   * The `verifyAccessToken` of the client, unchanged. It is for requests with an access token, and it is the only part
   * of the pipeline that calls Auth0.
   */
  verifyAccessToken(options: VerifyAccessTokenOptions): Promise<VerifiedAccessTokenClaims>;

  /**
   * The values the `aud` of a Session JWT may have for this request, compared character by character. `unverifiedAud`
   * is the `aud` of the Session JWT. It is signed, but it is only a claim of the agent until it is found in this list,
   * so a `domains` function receives it as `unverifiedIss`.
   */
  audiences(context: {
    url: string;
    headers: VerifyPoppyRequestOptions['headers'];
    unverifiedAud: string;
  }): Promise<readonly string[]>;

  /**
   * Gives `error` the `WWW-Authenticate` challenges that `verifyAccessToken` gives its own `invalid_request` errors
   * (RFC 6750, section 3.1), for the DPoP mode of the client, and returns it. The pipeline uses it for the one
   * `invalid_request` error that it throws itself.
   */
  addChallenges(error: InvalidRequestError): InvalidRequestError;
}

const HEADERS_NOT_A_PLAIN_OBJECT_MESSAGE =
  'Invalid poppy configuration: verifyPoppyRequest needs "headers" to be a plain object. ' +
  'For a Fetch API Request use Object.fromEntries(request.headers).';

/**
 * Whether `headers` is a plain record of header names, as `request.headers` of Node.js is. A Fetch API `Headers`, a
 * `Map`, an array and any other iterable are not, and neither is an object with a `get` method: reading them as a
 * record finds no header, and a request with no header reads as a request with no credentials. A header called `get`
 * with a string value is a plain record.
 */
function isPlainHeaders(headers: unknown): boolean {
  return (
    typeof headers === 'object' &&
    headers !== null &&
    !(Symbol.iterator in headers) &&
    typeof (headers as { get?: unknown }).get !== 'function'
  );
}

// `Bearer <token>` or `DPoP <token>` in any letter case, as `getToken` reads an `Authorization` header (RFC 6750,
// section 2.1, and RFC 9449, section 7.1).
const CREDENTIAL_PATTERN = /^(Bearer|DPoP) (.+)$/i;

/** Whether the request has an `Authorization` header, whether it is one credential or not. */
function hasAuthorization(headers: PoppyRequestHeaders): boolean {
  return headers.authorization !== undefined || headers.authorizationMalformed;
}

/**
 * The scheme, in lower case, and the token of the `Authorization` header. A value that is not `Bearer <token>` or
 * `DPoP <token>` keeps the scheme word it starts with and gets an empty token, so that `verifyAccessToken` answers with
 * its own challenge for it. Call it only when {@link hasAuthorization} is true.
 */
function readCredential(
  pipeline: PoppyPipeline,
  headers: PoppyRequestHeaders
): { scheme: string; accessToken: string } {
  const value = headers.authorization;
  // The flag is tested as `hasAuthorization` tests it, and not inferred from a missing value, so this refusal does not
  // depend on the reader leaving `authorization` out whenever it sets the flag.
  if (headers.authorizationMalformed || value === undefined) {
    // Two or more values, or a comma: not one credential, so there is no scheme and no token to read.
    const error = new InvalidRequestError(AUTHORIZATION_MALFORMED_MESSAGE);
    error.cause = { code: 'authorization_malformed' };
    throw pipeline.addChallenges(error);
  }

  const [, scheme, accessToken] = CREDENTIAL_PATTERN.exec(value) ?? [];
  if (scheme === undefined || accessToken === undefined) {
    return { scheme: (value.split(' ', 1)[0] ?? '').toLowerCase(), accessToken: '' };
  }
  return { scheme: scheme.toLowerCase(), accessToken };
}

/**
 * Verifies the access token with `verifyAccessToken`, which keeps all of its rules: the DPoP mode of the client, the
 * proof of a token that is bound to a key, and the refusal of a bound token sent as Bearer. Its errors reach the caller
 * as they are, with their challenges.
 *
 * `url` is the URL that the `htu` of the Session JWT is checked against, so a DPoP proof is checked against the public
 * URL of the API as well, and not against the address that a proxy gives the server. It is given to `verifyAccessToken`
 * as `httpUrl`. Leave it out when the token step has no use for it (see {@link verifyTokenRequest}).
 */
function verifyToken(
  pipeline: PoppyPipeline,
  request: VerifyPoppyRequestOptions,
  headers: PoppyRequestHeaders,
  credential: { scheme: string; accessToken: string },
  url?: string
): Promise<VerifiedAccessTokenClaims> {
  const { scheme, accessToken } = credential;
  const common = { accessToken, scheme, headers: request.headers, ...(url === undefined ? {} : { httpUrl: url }) };
  // A proof is passed with a Bearer token only when the request has one, because `verifyAccessToken` refuses a proof
  // for a token that is not bound. A DPoP request without a proof is passed as it is: it gets the standard challenge.
  const options =
    scheme === 'dpop'
      ? { ...common, dpopProof: headers.dpop, httpMethod: request.method }
      : { ...common, ...(headers.dpop === undefined ? {} : { dpopProof: headers.dpop }) };
  // The cast is for what the types cannot say: `scheme` is an arbitrary string, as the client sent it, so the compiler
  // cannot tell which of the two option types it goes with. The proof is `undefined` for a DPoP request that sent none,
  // and a Bearer token can come with a proof. `verifyAccessToken` has a rule for each of these, and one for a scheme it
  // does not accept.
  return pipeline.verifyAccessToken(options as VerifyAccessTokenOptions);
}

/**
 * The first of `client_id` and `azp` that is a string in the claims: the URL of the agent that the token was issued to,
 * if the token names one. Auth0 puts it in exactly one of them, as its token profile says.
 */
function agentClientOf(claims: VerifiedAccessTokenClaims): string | undefined {
  for (const name of DEFAULT_AGENT_CLIENT_ID_CLAIMS) {
    const value = claims[name];
    if (typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}

/**
 * Verifies the Session JWT of a `Poppy-Session` header, and the access token that comes with it, if there is one. The
 * Session is signed out without a token and signed in with one.
 */
async function verifyHeaderSession(
  pipeline: PoppyPipeline,
  request: VerifyPoppyRequestOptions,
  headers: PoppyRequestHeaders,
  jwt: string
): Promise<VerifiedPoppyRequest & { poppy: PoppySession }> {
  const { options, delegations } = pipeline;

  // Neither the parsing nor the allow list fetches anything, so a value that is no Session JWT, and an agent that is
  // not allowed, cost no request.
  const session = parseSessionJwt(jwt);
  const { iss, aud, sid, sub, agent_id: agentId, ath } = session.claims;
  if (options.agents !== undefined && !options.agents.has(iss)) {
    throw new InvalidSessionError('agent_not_allowed');
  }

  // The signature comes before the claims: no claim is used until it is verified, and a `domains` function of the
  // application is not called with one.
  const delegation = await delegations.verify(session.header.poppy_dlg, iss);
  await verifySessionSignature(session, delegation);
  const url = expectedRequestUrl(request.url, options.publicOrigin);
  const audiences = await pipeline.audiences({ url: request.url, headers: request.headers, unverifiedAud: aud });
  checkSessionClaims(session, { audiences, method: request.method, url, iatWindowSeconds: options.iatWindowSeconds });

  let claims: VerifiedAccessTokenClaims | undefined;
  if (hasAuthorization(headers)) {
    const credential = readCredential(pipeline, headers);
    // Before the token is verified: the hash needs only the token as it came, and a Session that is wrong then costs no
    // request to Auth0. A value that holds no token has no hash, and `verifyAccessToken` answers it below.
    if (credential.accessToken !== '' && ath !== (await computeAth(credential.accessToken))) {
      throw new InvalidSessionError('ath_mismatch');
    }
    claims = await verifyToken(pipeline, request, headers, credential, url);
    // The token must belong to the agent of the Session, and a token that names no agent does not.
    if (agentClientOf(claims) !== iss) {
      throw new InvalidSessionError('token_client_mismatch');
    }
  } else if (ath !== undefined) {
    // Spec section 5.3, step 3: without an access token, `ath` MUST be absent.
    throw new InvalidSessionError('ath_mismatch');
  }

  // A member is set only when it has a value, so the Session has no key that is `undefined`.
  const poppy: PoppySession = {
    sessionId: sid,
    key: await computeSessionKey(iss, sid),
    userId: sub,
    agent: agentId === undefined ? { cimdUrl: iss } : { cimdUrl: iss, poppyAgentId: agentId },
    state: claims === undefined ? 'signed_out' : 'signed_in',
    source: 'header',
  };

  // Last, so that nothing is saved for a Session that failed an earlier check.
  if (options.sessionStore !== undefined) {
    await checkSessionRecord(options.sessionStore, poppy);
  }
  return claims === undefined ? { poppy } : { poppy, claims };
}

/**
 * Verifies the access token of a request that has no Session header to use, and reads the Session from the `act` claim
 * of the token, if it has one. `check` is whether Session checks are on.
 *
 * The URL of the request is worked out only when the token step uses it: for a DPoP proof, which is checked against it,
 * and for a `domains` function, which receives it. A Bearer token without such a function is verified without it, so a
 * request with only a token may give a path, and no public origin is needed.
 */
async function verifyTokenRequest(
  pipeline: PoppyPipeline,
  request: VerifyPoppyRequestOptions,
  headers: PoppyRequestHeaders,
  check: boolean
): Promise<VerifiedPoppyRequest> {
  const { options } = pipeline;

  const credential = readCredential(pipeline, headers);
  const url =
    credential.scheme === 'dpop' || pipeline.hasDomainsResolver
      ? expectedRequestUrl(request.url, options.publicOrigin)
      : undefined;
  const claims = await verifyToken(pipeline, request, headers, credential, url);

  // A registered agent sends the header with every request (spec section 5.2), so its token without one is refused,
  // whatever its `act` claim holds. The claim is read from the verified token, and so is not the agent's own word.
  const client = agentClientOf(claims);
  if (check && client !== undefined && options.agents?.has(client)) {
    throw new InvalidSessionError('missing_session', REGISTERED_AGENT_NEEDS_SESSION_MESSAGE);
  }

  const fromToken = sessionFromToken(claims);
  if (fromToken === undefined) {
    return { claims };
  }

  const poppy: PoppySession = {
    sessionId: fromToken.sessionId,
    key: await computeSessionKey(fromToken.agent.cimdUrl, fromToken.sessionId),
    userId: fromToken.userId,
    agent: fromToken.agent,
    // A token was verified, so this Session is signed in, unless the token is the token of a guest: an anonymous user
    // has no account, so a Session with a guest is signed out, as a Session from the header with no token is.
    state: isGuestToken(claims) ? 'signed_out' : 'signed_in',
    source: 'token',
  };
  if (options.sessionStore !== undefined) {
    await checkSessionRecord(options.sessionStore, poppy);
  }
  return { poppy, claims };
}

/**
 * Verifies the Poppy Session of a request, for `ApiClient.verifyPoppyRequest`, which documents the checks, their order
 * and the errors.
 *
 * @returns `{ poppy, claims }` with the verified Session and the claims of the access token, either one left out when
 * the request has none, or `{}` when it has neither.
 * @throws {InvalidConfigurationError} When `request.headers` is not a plain object: a `Headers`, a `Map`, an array or
 * any other iterable, or an object with a `get` method.
 */
export async function verifyPoppyRequest(
  pipeline: PoppyPipeline,
  request: VerifyPoppyRequestOptions
): Promise<VerifiedPoppyRequest> {
  // Before anything else, whatever the checks are: a `Headers` object read as a record has no header, and the request
  // would pass as one with no credentials.
  if (!isPlainHeaders(request.headers)) {
    throw new InvalidConfigurationError(HEADERS_NOT_A_PLAIN_OBJECT_MESSAGE);
  }
  const headers = readPoppyRequestHeaders(request.headers);
  const requireSession = request.requireSession === true;
  const check = pipeline.options.verifySession || requireSession;

  // With checks off the header is not looked at, whatever it holds.
  if (check) {
    if (headers.sessionMalformed) {
      throw new InvalidSessionError('malformed_session');
    }
    if (headers.session !== undefined) {
      return verifyHeaderSession(pipeline, request, headers, headers.session);
    }
  }

  const result = hasAuthorization(headers) ? await verifyTokenRequest(pipeline, request, headers, check) : {};
  if (requireSession && result.poppy === undefined) {
    throw new InvalidSessionError('missing_session');
  }
  return result;
}
