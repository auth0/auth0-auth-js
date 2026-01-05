import { createHash } from 'crypto';
import {
  EmbeddedJWK,
  base64url,
  calculateJwkThumbprint,
  jwtVerify,
  type JWK,
  type JWTHeaderParameters,
  type JWTPayload,
} from 'jose';
import { InvalidDpopProofError, InvalidRequestError, VerifyAccessTokenError } from './errors.js';

export type ChallengeParams = {
  error?: string;
  errorDescription?: string;
  dpopError?: string;
  dpopErrorDescription?: string;
};

export type DPoPVerificationOptions = {
  proof: string;
  accessToken: string;
  method: string;
  url: string;
  cnfJkt?: string;
  iatOffset: number;
  iatLeeway: number;
  algorithms: readonly string[];
};

export const DPOP_ERROR_MESSAGES = {
  PROOF_VERIFICATION_FAILED: 'Failed to verify DPoP proof',
  MISSING_PROOF: 'Missing DPoP proof',
  MULTIPLE_PROOFS: 'Multiple DPoP proofs are not allowed',
  MISSING_CNF_JKT: 'Access token is missing cnf.jkt confirmation claim',
  INVALID_IAT: '"iat" claim must be a number',
  INVALID_JTI: '"jti" claim must be a string',
  INVALID_HTM: '"htm" claim must be a string',
  INVALID_HTU: '"htu" claim must be a string',
  INVALID_HTU_URL: '"htu" claim URL must be valid URL',
  INVALID_HTU_URL_HOST: 'Invalid "htu" claim URL: Host contains illegal characters or format',
  INVALID_HTU_URL_PATH: 'Invalid "htu" claim URL: Path must not start with "//"',
  INVALID_HTTP_URL: '"httpUrl" must be a valid URL',
  INVALID_HTTP_URL_HOST: 'Invalid "httpUrl": Host contains illegal characters or format',
  INVALID_HTTP_URL_PATH: 'Invalid "httpUrl": Path must not start with "//"',
  INVALID_ATH: '"ath" claim must be a string',
  IAT_MISMATCH: 'DPoP proof "iat" is outside the acceptable range',
  HTM_MISMATCH: 'DPoP proof "htm" mismatch',
  HTU_MISMATCH: 'DPoP proof "htu" mismatch',
  ATH_MISMATCH: 'DPoP proof "ath" mismatch',
  JWT_AT_MISMATCH: 'JWT Access Token confirmation mismatch',
  MISSING_JWK: 'Missing or invalid jwk in DPoP proof header',
  PRIVATE_KEY_MATERIAL: 'DPoP proof header must not contain private key material',
};

// Currently, only ES256 is supported.
export const ALLOWED_DPOP_ALGORITHMS = ['ES256'] as const;

function normalizePercentEncodings(s: string): string {
  const UNRESERVED = /[A-Za-z0-9\-._~]/;
  return s.replace(/%[0-9a-fA-F]{2}/g, (m) => {
    const byte = parseInt(m.slice(1), 16);
    const ch = String.fromCharCode(byte);
    return UNRESERVED.test(ch) ? ch : `%${m.slice(1).toUpperCase()}`;
  });
}

/**
 * Normalize a URL for DPoP `htu` comparison.
 *
 * Behavior:
 * - Parses with WHATWG `URL`; rejects invalid input.
 * - Host must be a valid hostname with optional `:port`; no schemes, slashes, queries, or fragments allowed.
 * - For `source === 'request'`: path must start with `/` and not look like a protocol.
 * - Removes query and fragment.
 * - Normalizes percent-encodings in the path.
 * - Returns `origin + pathname` for reliable comparison.
 *
 * @param input - The URL to normalize (either the inbound request URL or the `htu` claim).
 * @param source - Indicates whether `input` is from the HTTP request (`'request'`) or the DPoP proof (`'proof'`).
 * @returns The normalized URL string in the form `origin + pathname` (no query or fragment).
 * @throws {InvalidRequestError} When `source === 'request'` and parsing/validation fails.
 * @throws {InvalidDPoPProofError}   When `source === 'proof'` and parsing/validation fails.
 */
export function normalizeUrl(input: string, source: 'request' | 'proof'): string {
  const HOST_RE = /^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;
  const PROTOCOL_IN_PATH_RE = /^\/[a-z][a-z0-9+.-]*:\/\//i;

  try {
    const url = new URL(input);
    const host = url.host;

    if (
      typeof host !== 'string' ||
      host.length === 0 ||
      host.includes('://') ||
      host.includes('/') ||
      host.includes('?') ||
      host.includes('#') ||
      !HOST_RE.test(host)
    ) {
      if (source === 'request') {
        throw new InvalidRequestError(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL_HOST);
      } else {
        throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_HTU_URL_HOST);
      }
    }

    if (source === 'request') {
      const path = url.pathname;
      if (PROTOCOL_IN_PATH_RE.test(path)) {
        throw new InvalidRequestError(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL_PATH);
      }
    }

    url.search = '';
    url.hash = '';
    url.pathname = normalizePercentEncodings(url.pathname);

    return url.origin + url.pathname;
  } catch (err) {
    if (source === 'request') {
      if (err instanceof InvalidRequestError) throw err;
      throw new InvalidRequestError(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL);
    }
    if (err instanceof InvalidDpopProofError) throw err;
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_HTU_URL);
  }
}

async function verifyProofJwt(
  proof: string,
  algorithms: readonly string[]
): Promise<{ header: JWTHeaderParameters; claims: JWTPayload }> {
  try {
    const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: [...algorithms],
    });

    return { header: protectedHeader, claims: payload };
  } catch (err) {
    let message = DPOP_ERROR_MESSAGES.PROOF_VERIFICATION_FAILED;
    if (err instanceof Error && err.message) {
      message = err.message;
    }
    throw new InvalidDpopProofError(message);
  }
}

export async function verifyDpopProof(options: DPoPVerificationOptions): Promise<void> {
  const { proof, accessToken, method, url, cnfJkt, iatOffset, iatLeeway, algorithms } = options;

  if (!proof) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.MISSING_PROOF);
  }

  if (proof.includes(',')) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.MULTIPLE_PROOFS);
  }

  if (!cnfJkt) {
    const err = new VerifyAccessTokenError(DPOP_ERROR_MESSAGES.MISSING_CNF_JKT);
    err.cause = { code: 'dpop_binding_mismatch' };
    throw err;
  }

  const normalizedRequestUrl = normalizeUrl(url, 'request');
  const { claims, header } = await verifyProofJwt(proof, algorithms);

  const { htm, htu, iat, ath, jti } = claims;

  if (typeof jti !== 'string' || !jti) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_JTI);
  }

  // Verify `iat` claim is present and is a number. This is redundant with `jose` but we double-check here.
  if (typeof iat !== 'number') {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_IAT);
  }

  const now = Math.floor(Date.now() / 1000);
  if (iat < now - iatOffset || iat > now + iatLeeway) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.IAT_MISMATCH);
  }

  if (typeof htm !== 'string') {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_HTM);
  }

  if (htm.toUpperCase() !== method.toUpperCase()) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.HTM_MISMATCH);
  }

  if (typeof htu !== 'string') {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_HTU);
  }

  const normalizedProofUrl = normalizeUrl(htu, 'proof');
  if (normalizedProofUrl !== normalizedRequestUrl) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.HTU_MISMATCH);
  }

  if (typeof ath !== 'string') {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.INVALID_ATH);
  }

  const hash = createHash('sha256').update(accessToken).digest();
  const encodedHash = base64url.encode(hash);
  if (ath !== encodedHash) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.ATH_MISMATCH);
  }

  // Verify the JWK is not malformed. This is redundant with `jose` but we double-check here.
  const jwk = header.jwk as JWK | undefined;
  if (!jwk || typeof jwk !== 'object') {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.MISSING_JWK);
  }

  // Ensure the JWK does not contain private key material. This is redundant with `jose` but we double-check here.
  if ('d' in jwk) {
    throw new InvalidDpopProofError(DPOP_ERROR_MESSAGES.PRIVATE_KEY_MATERIAL);
  }

  const thumbprint = await calculateJwkThumbprint(jwk);
  if (thumbprint !== cnfJkt) {
    const err = new VerifyAccessTokenError(DPOP_ERROR_MESSAGES.JWT_AT_MISMATCH);
    err.cause = { code: 'dpop_binding_mismatch' };
    throw err;
  }
}

export function buildChallenges(
  dpopMode: 'allowed' | 'required' | 'disabled',
  algorithms: readonly string[] = ALLOWED_DPOP_ALGORITHMS,
  params: ChallengeParams = {}
): Record<string, string | string[]> {
  const bearerParams = [
    'realm="api"',
    params.error ? `error="${params.error}"` : undefined,
    params.errorDescription ? `error_description="${params.errorDescription}"` : undefined,
  ]
    .filter(Boolean)
    .join(', ');

  const dpopParams = [
    params.dpopError ? `error="${params.dpopError}"` : undefined,
    params.dpopErrorDescription ? `error_description="${params.dpopErrorDescription}"` : undefined,
    `algs="${algorithms.join(' ')}"`,
  ]
    .filter(Boolean)
    .join(', ');

  const bearerValue = `Bearer ${bearerParams}`;
  const dpopValue = `DPoP ${dpopParams}`;

  const challenges: string[] = [];

  if (dpopMode === 'allowed') {
    challenges.push(bearerValue, dpopValue);
  } else if (dpopMode === 'required') {
    challenges.push(dpopValue);
  } else {
    challenges.push(bearerValue);
  }

  return {
    'www-authenticate': challenges,
  };
}
