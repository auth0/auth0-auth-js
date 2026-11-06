import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  MAX_SESSION_ID_LENGTH,
  MAX_SESSION_JWT_LENGTH,
  SESSION_ID_PATTERN,
  SESSION_JWT_ALGORITHMS,
  SESSION_JWT_TYP,
} from './constants.js';
import { InvalidSessionError } from './errors.js';
import { isAgentUrl } from './url-rules.js';

// Reads the Session JWT of a `Poppy-Session` header, and checks that it has the shape that every later step relies on.
// It is the first step of a request, before anything is fetched, so it is strict and cheap, and it trusts nothing: the
// signature, the delegation, the agent and the claims are verified later, and a value read here is only a claim.
// Spec: https://personalagentprotocol.org/docs/0.3/spec, section 5.2 (the Session header, and Delegated keys).

// What a failed check says. It names the check and never a value of the JWT, because the text goes into the response to
// a caller that is not trusted, and into logs.
const MALFORMED_MESSAGES = {
  shape: 'The Session JWT must be in compact form: three parts of base64url characters, separated by dots.',
  tooLong: `The Session JWT must be at most ${MAX_SESSION_JWT_LENGTH} characters.`,
  header: 'The Session JWT header must be a base64url-encoded JSON object.',
  payload: 'The Session JWT payload must be a base64url-encoded JSON object.',
  typ: `The Session JWT typ header must be ${SESSION_JWT_TYP}.`,
  alg: `The Session JWT alg header must be ${SESSION_JWT_ALGORITHMS.join(' or ')}.`,
  kid: 'The Session JWT kid header must be a non-empty string.',
  delegation: 'The Session JWT poppy_dlg header must be a JWT in compact form.',
  iss: 'The Session JWT iss claim must be the https URL of an agent.',
  aud: 'The Session JWT aud claim must be a single string.',
  sid: `The Session JWT sid claim must be 1 to ${MAX_SESSION_ID_LENGTH} characters of the base64url alphabet.`,
  sub: 'The Session JWT sub claim must be a non-empty string.',
  jti: 'The Session JWT jti claim must be a non-empty string.',
  htm: 'The Session JWT htm claim must be a string.',
  htu: 'The Session JWT htu claim must be a string.',
  iat: 'The Session JWT iat claim must be a finite number.',
  agentId: 'The Session JWT agent_id claim must be left out or be a non-empty string.',
  ath: 'The Session JWT ath claim must be left out or be a non-empty string.',
} as const;

// The compact serialization of a JWS (RFC 7515, section 7.1): three parts, each one or more characters of the base64url
// alphabet (RFC 4648, section 5) with no padding, separated by dots. The dot is not in the alphabet, so each part ends
// where the next dot is, and the pattern runs in linear time. It also refuses what a lenient base64 decoder would skip,
// such as a space, a line break, `=` or the `+` and `/` of standard base64.
const COMPACT_JWS_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

const MEDIA_TYPE_PREFIX = 'application/';

// An algorithm of a Session JWT, as a type made from the list that the SDK checks against. Adding an algorithm to the
// list adds it to the type, so the type cannot say less or more than the check does.
type SessionJwtAlgorithm = (typeof SESSION_JWT_ALGORITHMS)[number];

/**
 * A Session JWT that was read and checked for its shape, and for nothing more. Nothing in it is verified: the
 * signature, the delegation, the agent and the claims are checked by later steps, so none of these values can be
 * trusted yet. Never use one of them to look up or to attribute anything before the Session is verified.
 */
export interface UnverifiedSessionJwt {
  /** The JWT as it came in. */
  jwt: string;

  /** The header parameters the SDK uses. The other parameters of the JWT are left out, whatever they are. */
  header: {
    /** As the JWT has it. It is `poppy-session+jwt` in any letter case, with `application/` before it or not. */
    typ: string;
    /** `ES256`, the only algorithm of a Session JWT. */
    alg: SessionJwtAlgorithm;
    /** The thumbprint of the delegated key, which a later step compares with the key of the delegation. */
    kid: string;
    /** The delegation, in compact form. Its content is not read here. */
    poppy_dlg: string;
  };

  /** The claims the SDK uses. The other claims of the JWT are left out, whatever they are. */
  claims: {
    iss: string;
    aud: string;
    sid: string;
    sub: string;
    agent_id?: string;
    htm: string;
    htu: string;
    iat: number;
    jti: string;
    ath?: string;
  };
}

/**
 * Normalizes the `typ` header of a JWT the way `jose` compares it: in lower case, and without one `application/` at the
 * start. RFC 7515, section 4.1.9, says that media type names are not case sensitive, and that `application/` may be
 * left out of a `typ` that has no other slash.
 *
 * Compare the result with a type that is in this form already, such as `poppy-session+jwt`. The same rule applies to
 * the `typ` of a delegation, `poppy-delegation+jwt`.
 *
 * @param typ - The `typ` header, as the JWT has it.
 * @returns The `typ` without letter case and without `application/`.
 */
export function normalizeTyp(typ: string): string {
  const lowerCase = typ.toLowerCase();
  return lowerCase.startsWith(MEDIA_TYPE_PREFIX) ? lowerCase.slice(MEDIA_TYPE_PREFIX.length) : lowerCase;
}

function malformed(message: string): InvalidSessionError {
  return new InvalidSessionError('malformed_session', message);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

function isOptionalNonEmptyString(value: unknown): value is string | undefined {
  return value === undefined || isNonEmptyString(value);
}

// The answer and the type come from the same list, so the type is true by construction.
function isSessionAlgorithm(alg: unknown): alg is SessionJwtAlgorithm {
  return SESSION_JWT_ALGORITHMS.some((algorithm) => algorithm === alg);
}

/**
 * Reads a Session JWT without trusting it, and checks its shape. This is the first step for the value of a
 * `Poppy-Session` header: it makes no network call and verifies no signature, so what it returns is not verified.
 *
 * It throws when:
 * - the JWT is longer than {@link MAX_SESSION_JWT_LENGTH}, or is not three parts of base64url characters separated
 *   by dots, or the header or the payload is not a base64url-encoded JSON object;
 * - `typ` is not `poppy-session+jwt` (see {@link normalizeTyp}), `alg` is not `ES256`, `kid` is not a non-empty
 *   string, or `poppy_dlg` is not a JWT in compact form;
 * - `iss` is not an agent URL, `aud` is not a single string (an array is refused), `sid` is not a Session ID,
 *   `sub` or `jti` is not a non-empty string, `htm` or `htu` is not a string, or `iat` is not a finite number;
 * - `agent_id` or `ath` is there and is not a non-empty string.
 *
 * The error message names the check that failed, and never has a value from the JWT in it.
 *
 * The result is a new object that holds the documented members only. Other header parameters, such as `jwk`, `jku` and
 * `x5u`, and other claims are left out.
 *
 * @param jwt - The value of the `Poppy-Session` header.
 * @returns The header and the claims of the JWT, not verified.
 * @throws {InvalidSessionError} With reason `malformed_session` when a check fails. It throws nothing else.
 */
export function parseSessionJwt(jwt: string): UnverifiedSessionJwt {
  if (typeof jwt !== 'string') {
    throw malformed(MALFORMED_MESSAGES.shape);
  }
  // The length first, so a huge value costs nothing.
  if (jwt.length > MAX_SESSION_JWT_LENGTH) {
    throw malformed(MALFORMED_MESSAGES.tooLong);
  }
  if (!COMPACT_JWS_PATTERN.test(jwt)) {
    throw malformed(MALFORMED_MESSAGES.shape);
  }

  // `jose` types the result by what a header and a claim should be, and the content is JSON of any shape, so every
  // member is read as `unknown` and checked.
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(jwt);
  } catch {
    throw malformed(MALFORMED_MESSAGES.header);
  }

  const { typ, alg, kid, poppy_dlg: delegation } = header;
  if (typeof typ !== 'string' || normalizeTyp(typ) !== SESSION_JWT_TYP) {
    throw malformed(MALFORMED_MESSAGES.typ);
  }
  if (!isSessionAlgorithm(alg)) {
    throw malformed(MALFORMED_MESSAGES.alg);
  }
  if (!isNonEmptyString(kid)) {
    throw malformed(MALFORMED_MESSAGES.kid);
  }
  if (typeof delegation !== 'string' || !COMPACT_JWS_PATTERN.test(delegation)) {
    throw malformed(MALFORMED_MESSAGES.delegation);
  }

  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(jwt);
  } catch {
    throw malformed(MALFORMED_MESSAGES.payload);
  }

  const { iss, aud, sid, sub, jti, htm, htu, iat, agent_id: agentId, ath } = claims;
  if (!isAgentUrl(iss)) {
    throw malformed(MALFORMED_MESSAGES.iss);
  }
  if (typeof aud !== 'string') {
    throw malformed(MALFORMED_MESSAGES.aud);
  }
  // `RegExp.test` turns a number or an array into text, so the type is checked first.
  if (typeof sid !== 'string' || !SESSION_ID_PATTERN.test(sid)) {
    throw malformed(MALFORMED_MESSAGES.sid);
  }
  if (!isNonEmptyString(sub)) {
    throw malformed(MALFORMED_MESSAGES.sub);
  }
  if (!isNonEmptyString(jti)) {
    throw malformed(MALFORMED_MESSAGES.jti);
  }
  if (typeof htm !== 'string') {
    throw malformed(MALFORMED_MESSAGES.htm);
  }
  if (typeof htu !== 'string') {
    throw malformed(MALFORMED_MESSAGES.htu);
  }
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    throw malformed(MALFORMED_MESSAGES.iat);
  }
  if (!isOptionalNonEmptyString(agentId)) {
    throw malformed(MALFORMED_MESSAGES.agentId);
  }
  if (!isOptionalNonEmptyString(ath)) {
    throw malformed(MALFORMED_MESSAGES.ath);
  }

  // A new object with the documented members, so nothing else that the JWT carries reaches a later step.
  return {
    jwt,
    header: { typ, alg, kid, poppy_dlg: delegation },
    claims: {
      iss,
      aud,
      sid,
      sub,
      ...(agentId === undefined ? {} : { agent_id: agentId }),
      htm,
      htu,
      iat,
      jti,
      ...(ath === undefined ? {} : { ath }),
    },
  };
}
