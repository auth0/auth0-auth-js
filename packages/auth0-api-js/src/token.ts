/**
 * Header-like object that can represent headers from different HTTP frameworks
 */
type HeadersLike = Record<string, unknown> & {
  authorization?: string;
  'content-type'?: string;
};

/**
 * Query-like object for URL query parameters
 */
type QueryLike = Record<string, unknown> & { access_token?: string };

/**
 * Body-like object for form-encoded request body
 */
type BodyLike = QueryLike;

/**
 * Regular expression to match Bearer token in Authorization header
 */
const TOKEN_RE = /^Bearer (.+)$/i;

/**
 * Extracts a Bearer token from HTTP request according to RFC 6750.
 * Supports all three methods defined in the RFC:
 * - Authorization header (Section 2.1)
 * - Form-encoded body parameter (Section 2.2)
 * - URI query parameter (Section 2.3)
 *
 * @param headers - HTTP headers object
 * @param query - Query parameters object (optional)
 * @param body - Request body object (optional)
 * @returns The extracted token string
 * @throws {Error} When no token is found or multiple methods are used
 *
 * @example
 * ```typescript
 * // Authorization header method (recommended)
 * const token1 = getToken({ authorization: 'Bearer mF_9.B5f-4.1JqM' });
 *
 * // Query parameter method
 * const token2 = getToken({}, { access_token: 'mF_9.B5f-4.1JqM' });
 *
 * // Form body method
 * const token3 = getToken(
 *   { 'content-type': 'application/x-www-form-urlencoded' },
 *   {},
 *   { access_token: 'mF_9.B5f-4.1JqM' }
 * );
 *
 * // Express.js usage
 * const token4 = getToken(req.headers, req.query, req.body);
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-2 - RFC 6750 Section 2
 */
export function getToken(
  headers: HeadersLike,
  query?: QueryLike,
  body?: BodyLike
): string {
  const fromHeader = getTokenFromHeader(headers);
  const fromQuery = getTokenFromQuery(query);
  const fromBody = getTokenFromBody(headers, body);

  if (!fromQuery && !fromHeader && !fromBody) {
    throw new Error('No Bearer token found in request');
  }

  // If multiple methods are used, throw an error
  if (+!!fromQuery + +!!fromBody + +!!fromHeader > 1) {
    throw new Error('More than one method used for authentication');
  }

  return (fromQuery || fromBody || fromHeader) as string;
}

/**
 * Extract token from Authorization header
 */
function getTokenFromHeader(headers: HeadersLike) {
  const authHeader = headers.authorization;
  if (typeof authHeader !== 'string') {
    return undefined;
  }

  const match = authHeader.match(TOKEN_RE);
  return match?.[1];
}

/**
 * Extract token from query parameters
 */
function getTokenFromQuery(query?: QueryLike): string | undefined {
  const accessToken = query?.access_token;
  if (typeof accessToken === 'string') {
    return accessToken;
  }
}

/**
 * Extract token from form-encoded body
 */
function getTokenFromBody(
  headers: HeadersLike,
  body?: BodyLike
): string | undefined {
  if (!body || typeof body.access_token !== 'string') {
    return undefined;
  }

  const contentType = headers['content-type'];
  if (!contentType) {
    return undefined;
  }

  // Handle content-type with charset, e.g., "application/x-www-form-urlencoded; charset=utf-8"
  const isFormEncoded = contentType
    .toLowerCase()
    .includes('application/x-www-form-urlencoded');
  if (!isFormEncoded) {
    return undefined;
  }

  return body.access_token;
}
