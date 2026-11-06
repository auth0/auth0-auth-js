import { AuthError } from '../errors.js';

/**
 * An HTTP response for an error: the status, the headers and, for Session errors, a JSON body.
 *
 * @beta
 * @category Poppy
 */
export interface HttpErrorResponse {
  /**
   * The HTTP status code.
   */
  status: number;

  /**
   * The response headers, such as `www-authenticate` or `retry-after`. This is a copy, array values included:
   * changing it does not change the error. The record is made for `res.set(headers)` of Express and
   * `reply.headers(headers)` of Fastify. For the Fetch API, see the `toResponse` helper in
   * [Turn errors into responses](./EXAMPLES.md#turn-errors-into-responses).
   */
  headers: Record<string, string | string[]>;

  /**
   * The JSON body. Absent when the response has none.
   */
  body?: { error: string; error_description?: string };
}

// Access token errors live in the `WWW-Authenticate` header and have no JSON body (spec section 7). The Session
// errors have a body, and so has the 503 for an agent host that can't be reached.
const JSON_BODY_CODES: ReadonlySet<string> = new Set(['invalid_session', 'session_ended', 'temporarily_unavailable']);

// A header value is a string or a list of strings, such as the `www-authenticate` challenges. Copying the lists too
// means the response never shares an array with the error.
function copyHeaders(headers: Record<string, string | string[]> | undefined): Record<string, string | string[]> {
  return Object.fromEntries(
    Object.entries(headers ?? {}).map(([name, value]) => [name, Array.isArray(value) ? [...value] : value])
  );
}

/**
 * Turns an error thrown by this package into the HTTP response the Poppy specification asks for (section 7), so a
 * framework adapter does not have to map each error itself.
 *
 * - `invalid_session` and `session_ended` get status 400 and a JSON body `{ error, error_description }`.
 * - `temporarily_unavailable` gets status 503, a `retry-after` header and a JSON body.
 * - Access token errors, `sign_in_required` and the other `AuthError`s get their `statusCode` and `headers` (the
 *   `WWW-Authenticate` challenges) and no body.
 *
 * `error_description` is the message of the error, left out when the message is empty.
 *
 * @example
 * ```typescript
 * try {
 *   const result = await apiClient.verifyPoppyRequest({ method, url, headers });
 * } catch (error) {
 *   const response = toHttpErrorResponse(error);
 *   if (!response) throw error;
 *   reply.code(response.status).headers(response.headers).send(response.body);
 * }
 * ```
 *
 * @param error - Anything that was thrown.
 * @returns The response for an `AuthError` that has a `statusCode`, and `undefined` for any other value. For
 * `undefined`, rethrow the error: this package does not know how to answer it.
 *
 * @beta
 * @category Poppy
 */
export function toHttpErrorResponse(error: unknown): HttpErrorResponse | undefined {
  if (!(error instanceof AuthError) || typeof error.statusCode !== 'number') {
    return undefined;
  }

  const body = JSON_BODY_CODES.has(error.code)
    ? { error: error.code, ...(error.message ? { error_description: error.message } : {}) }
    : undefined;

  return { status: error.statusCode, headers: copyHeaders(error.headers), body };
}
