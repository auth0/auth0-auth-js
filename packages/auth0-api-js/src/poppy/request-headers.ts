import { POPPY_SESSION_HEADER } from './constants.js';

// Reads the three headers a Poppy request is made of, whatever shape the header record has: names in any case, and
// values that are a string or an array of strings. It trims the values, counts them, joins the `DPoP` values, and flags
// a header that cannot be one Session JWT or one credential. It never throws, and it never decides that a request is
// wrong: the pipeline does that. It acts on a malformed `Poppy-Session` header only when Session checks run, and on a
// malformed `Authorization` header whenever the request has one.
// Spec: https://personalagentprotocol.org/docs/0.3/spec, section 5.2 (the `Poppy-Session` header).

const AUTHORIZATION_HEADER = 'authorization';
const DPOP_HEADER = 'dpop';

/**
 * The three headers of a Poppy request, as {@link readPoppyRequestHeaders} reads them. A header that the request does
 * not have is `undefined`. The values are trimmed and counted, and a header that cannot be one Session JWT or one
 * credential is flagged as malformed. Only the shape of a value is looked at: how many values the header has, and
 * whether a value is empty or has a comma. A value is not parsed.
 */
export interface PoppyRequestHeaders {
  /**
   * The `Poppy-Session` value, trimmed, when the header has exactly one value and it can be one JWT. `undefined` when
   * the header is not there, and when it is malformed.
   */
  session?: string;

  /**
   * Whether the `Poppy-Session` header is there and is not one JWT, which is when it has two or more values, a comma in
   * its value, or no value but spaces and tabs. A JWT has no comma, so a comma means that several JWTs were joined,
   * as a proxy or `Object.fromEntries(request.headers)` does with a header that was sent twice.
   */
  sessionMalformed: boolean;

  /**
   * The `Authorization` value, trimmed, when the header has exactly one value, and it is not empty and has no comma.
   * `undefined` when the header is not there, when its only value is empty, and when it is malformed.
   */
  authorization?: string;

  /**
   * Whether the `Authorization` header has two or more values, or a comma in its one value. A Bearer or DPoP
   * credential has no comma, so a comma means that several headers were joined into one text, as the Fetch API
   * `Headers` does with a header that was sent twice.
   */
  authorizationMalformed: boolean;

  /**
   * The `DPoP` value, trimmed. When the header has several values they are joined with a comma and a space, so the
   * joined text is not a JWT and `verifyAccessToken` refuses it. A header whose only value is empty is `undefined`, as
   * if it was not sent. With several values an empty one still counts as a value, so a header that was sent twice is
   * never read as sent once.
   */
  dpop?: string;
}

// The optional whitespace around a field value is spaces and tabs only (RFC 9110, section 5.5). Another character,
// such as a line feed or a no-break space, is part of the value, and the parser of the Session JWT refuses it. Only the
// two ends are scanned. A pattern such as `/^[ \t]+|[ \t]+$/` is not an option: it starts again from every space of a
// long run in the middle of the value, so its time grows with the square of the length.
function isHttpWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09;
}

function trimHttpWhitespace(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && isHttpWhitespace(value.charCodeAt(start))) {
    start += 1;
  }
  while (end > start && isHttpWhitespace(value.charCodeAt(end - 1))) {
    end -= 1;
  }
  return value.slice(start, end);
}

/** The one value of a header, or `undefined` when it has none or several. */
function onlyValue(values: readonly string[]): string | undefined {
  return values.length === 1 ? values[0] : undefined;
}

// A header whose only value is empty reads as a header that was not sent. With two or more values, an empty one is
// still a value, so a header that was sent twice is never read as sent once.
function withoutOnlyEmptyValue(values: readonly string[]): readonly string[] {
  return values.length === 1 && values[0] === '' ? [] : values;
}

// A Session JWT is one value, and it is not empty. It has no comma, so a comma means that several JWTs were joined.
function readSession(values: readonly string[]): Pick<PoppyRequestHeaders, 'session' | 'sessionMalformed'> {
  const value = onlyValue(values);
  if (values.length > 1 || value === '' || value?.includes(',')) {
    return { session: undefined, sessionMalformed: true };
  }
  return { session: value, sessionMalformed: false };
}

// An access token credential is one value. A Bearer or DPoP credential has no comma, so a comma means that several
// headers were joined into one text, as a Fetch API record does with a header that was sent twice.
function readAuthorization(
  values: readonly string[]
): Pick<PoppyRequestHeaders, 'authorization' | 'authorizationMalformed'> {
  const present = withoutOnlyEmptyValue(values);
  const value = onlyValue(present);
  if (present.length > 1 || value?.includes(',')) {
    return { authorization: undefined, authorizationMalformed: true };
  }
  return { authorization: value, authorizationMalformed: false };
}

// Several proofs are joined, and the joined text is not a JWT, so `verifyAccessToken` refuses it.
function readDpop(values: readonly string[]): string | undefined {
  const present = withoutOnlyEmptyValue(values);
  return present.length > 0 ? present.join(', ') : undefined;
}

/**
 * Reads the `Poppy-Session`, `Authorization` and `DPoP` headers from a header record.
 *
 * - Names are matched without regard to case, so `Poppy-Session`, `poppy-session` and `POPPY-SESSION` are the same.
 *   Only the three names are read: `x-poppy-session` is not `poppy-session`.
 * - A header has one value for each string it has. A key that holds an array has one for each string in the array, and
 *   a record that holds the same name in two cases, such as `Poppy-Session` and `poppy-session`, has two values. An
 *   array of one is one value. A value that is not a string is ignored.
 * - Each value is trimmed of the spaces and tabs around it (RFC 9110, section 5.5) before it is used.
 * - `Poppy-Session` is malformed when it has two or more values, a comma in its value, or an empty value.
 * - `Authorization` is malformed when it has two or more values, or a comma in its value.
 * - The values of `DPoP` are joined with `', '`.
 * - For `Authorization` and `DPoP`, a header whose only value is empty reads as a header that was not sent. With two
 *   or more values an empty one still counts as a value.
 *
 * This function never throws, and a `headers` that is not an object reads as a record with none of the headers. It
 * reads headers only: a token or a Session in the URL or in the body is never used.
 *
 * @param headers - The request headers: `request.headers` of Node.js, or `Object.fromEntries(request.headers)` for a
 * Fetch API request.
 * @returns The three headers.
 */
export function readPoppyRequestHeaders(headers: Record<string, string | string[] | undefined>): PoppyRequestHeaders {
  const session: string[] = [];
  const authorization: string[] = [];
  const dpop: string[] = [];
  // A map and not an object, so a header named `constructor` or `__proto__` finds nothing.
  const valuesByName = new Map<string, string[]>([
    [POPPY_SESSION_HEADER, session],
    [AUTHORIZATION_HEADER, authorization],
    [DPOP_HEADER, dpop],
  ]);

  if (typeof headers === 'object' && headers !== null) {
    for (const [name, value] of Object.entries(headers)) {
      const values = valuesByName.get(name.toLowerCase());
      if (values === undefined) {
        continue;
      }
      for (const entry of Array.isArray(value) ? value : [value]) {
        if (typeof entry === 'string') {
          values.push(trimHttpWhitespace(entry));
        }
      }
    }
  }

  return { ...readSession(session), ...readAuthorization(authorization), dpop: readDpop(dpop) };
}
