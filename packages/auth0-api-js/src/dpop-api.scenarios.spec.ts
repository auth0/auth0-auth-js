import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

import { ApiClient } from './api-client.js';
import {
  InvalidDpopProofError,
  InvalidRequestError,
  VerifyAccessTokenError,
} from './errors.js';

const ERR_DESC = {
  DPOP_BOUND_BEARER: 'DPoP-bound token requires the DPoP authentication scheme, not Bearer',
  SIG_FAILURE: 'signature verification failed',
  CNF_MISSING: 'JWT Access Token has no jkt confirmation claim',
  DPOP_PROOF_FAIL: 'Failed to verify DPoP proof',
  DPOP_PROOF_REQUIRES_SCHEME: 'DPoP proof requires the DPoP authentication scheme, not Bearer',
  INVALID_JWS: 'Invalid Compact JWS',
} as const;

const issuer = 'https://client-using-dpop/';
const audience = 'https://server-expecting-dpop';

const discoveryUrl = `${issuer}.well-known/openid-configuration`;
const jwksUrl = `${issuer}.well-known/jwks.json`;

import type { JWK } from 'jose';
import { VerifyAccessTokenOptions } from './types.js';

let rsaPrivateKey: CryptoKey;
let rsaPublicJwk: JWK;
let badRsaPrivateKey: CryptoKey;
let ecPrivateKey: CryptoKey;
let ecPublicJwk: JWK;
let ecThumbprint: string;

const handlers = [
  http.get(discoveryUrl, () =>
    HttpResponse.json({
      issuer,
      jwks_uri: jwksUrl,
      token_endpoint: `${issuer}oauth/token`,
    })
  ),
  http.get(jwksUrl, () => HttpResponse.json({ keys: [rsaPublicJwk] })),
];

const server = setupServer(...handlers);

beforeAll(async () => {
  const rsa = await generateKeyPair('RS256');
  rsaPrivateKey = rsa.privateKey;
  rsaPublicJwk = await exportJWK(rsa.publicKey);
  (rsaPublicJwk as Record<string, unknown>).alg = 'RS256';

  badRsaPrivateKey = (await generateKeyPair('RS256')).privateKey;

  const ec = await generateKeyPair('ES256');
  ecPrivateKey = ec.privateKey;
  ecPublicJwk = await exportJWK(ec.publicKey);
  (ecPublicJwk as Record<string, unknown>).alg = 'ES256';
  ecThumbprint = await calculateJwkThumbprint(ecPublicJwk);

  server.listen({ onUnhandledRequest: 'error' });
});

afterAll(() => server.close());
afterEach(() => server.resetHandlers());

type TokenKind = 'valid-bearer-token' | 'valid-dpop-token' | 'invalid-token' | 'malformed-token' | 'empty';
type ProofKind = 'valid-proof' | 'invalid-proof' | 'none';

const signToken = async (kind: TokenKind, opts?: { cnfJkt?: string }): Promise<string> => {
  if (kind === 'empty') return '';
  if (kind === 'malformed-token') return 'not-a-jwt';

  const now = Math.floor(Date.now() / 1000);
  const builder = new SignJWT(opts?.cnfJkt ? { cnf: { jkt: opts.cnfJkt } } : {})
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .setSubject('user');

  const key = kind === 'invalid-token' ? badRsaPrivateKey : rsaPrivateKey;
  return builder.sign(key);
};

const makeProof = async (
  kind: ProofKind,
  accessToken: string,
  method: string,
  url: string
): Promise<string | undefined> => {
  if (kind === 'none') return undefined;

  const ath = await computeAth(accessToken);
  const payload: Record<string, unknown> = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: 'jti',
  };
  if (kind === 'valid-proof') {
    payload.ath = ath;
  } else {
    payload.ath = 'bad-ath';
  }

  const oneProof = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: ecPublicJwk })
    .sign(ecPrivateKey);

  return oneProof;
};

async function computeAth(token: string) {
  const data = new TextEncoder().encode(token);
  // Use subtle if available, fallback otherwise
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const b64 = btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return b64;
}

type Expectation = {
  ok?: boolean;
  statusCode?: number;
  code?: string;
  errorClass?: { name: string } | undefined;
  errorDescription?: string | RegExp;
  challenge?: string | RegExp;
};

type Scenario = {
  name: string;
  tokenKind: TokenKind;
  proofKind: ProofKind;
  scheme?: string;
  expect: Expectation;
};

const scenariosByMode: Record<'allowed' | 'required' | 'disabled', Scenario[]> = {
  allowed: [
    {
      name: 'bearer + DPoP-bound token + proof => invalid_token',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.DPOP_BOUND_BEARER,
        challenge: `Bearer realm="api", error="invalid_token", error_description="${ERR_DESC.DPOP_BOUND_BEARER}", DPoP algs="ES256"`,
      },
    },
    {
      name: 'bearer with blank token + proof => verify_access_token_error',
      tokenKind: 'empty',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: '',
        challenge: 'Bearer realm="api", DPoP algs="ES256"',
      },
    },
    {
      name: 'bearer invalid token => invalid_token',
      tokenKind: 'invalid-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.SIG_FAILURE,
        challenge: `Bearer realm="api", error="invalid_token", error_description="${ERR_DESC.SIG_FAILURE}", DPoP algs="ES256"`,
      },
    },
    {
      name: 'bearer DPoP-bound token (no proof) => invalid_token',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.DPOP_BOUND_BEARER,
        challenge: `Bearer realm="api", error="invalid_token", error_description="${ERR_DESC.DPOP_BOUND_BEARER}", DPoP algs="ES256"`,
      },
    },
    {
      name: 'valid bearer token => OK',
      tokenKind: 'valid-bearer-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: { ok: true },
    },
    {
      name: 'bearer malformed token => invalid_token',
      tokenKind: 'malformed-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        // jose error message for non-compact JWS input
        errorDescription: ERR_DESC.INVALID_JWS,
        challenge: `Bearer realm="api", error="invalid_token", error_description="${ERR_DESC.INVALID_JWS}", DPoP algs="ES256"`,
      },
    },
    {
      name: 'bearer + proof but token unbound => invalid_request',
      tokenKind: 'valid-bearer-token',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: ERR_DESC.DPOP_PROOF_REQUIRES_SCHEME,
        challenge: `Bearer realm="api", error="invalid_request", error_description="${ERR_DESC.DPOP_PROOF_REQUIRES_SCHEME}", DPoP algs="ES256"`,
      },
    },
    {
      name: 'DPoP token without proof => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api", DPoP algs="ES256"',
      },
    },
    {
      name: 'dpop scheme without cnf => invalid_token',
      tokenKind: 'valid-bearer-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.CNF_MISSING,
        challenge: `Bearer realm="api", DPoP error="invalid_token", error_description="${ERR_DESC.CNF_MISSING}", algs="ES256"`,
      },
    },
    {
      name: 'dpop invalid token + proof => invalid_token',
      tokenKind: 'invalid-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.SIG_FAILURE,
        challenge: `Bearer realm="api", DPoP error="invalid_token", error_description="${ERR_DESC.SIG_FAILURE}", algs="ES256"`,
      },
    },
    {
      name: 'missing Authorization header => invalid_request',
      tokenKind: 'empty',
      proofKind: 'none',
      scheme: 'none',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api", DPoP algs="ES256"',
      },
    },
    {
      name: 'unsupported scheme foo => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'unsupported_scheme',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api", DPoP algs="ES256"',
      },
    },
    {
      name: 'malformed DPoP scheme "DPoP dpop" => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'DPoP dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api", DPoP algs="ES256"',
      },
    },
    {
      name: 'Valid DPoP token with valid proof and random scheme => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'some_random_scheme',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api", DPoP algs="ES256"',
      },
    },
  ],

  required: [
    {
      name: 'bearer DPoP-bound token + proof => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'bearer blank token + proof => invalid_request',
      tokenKind: 'empty',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'bearer DPoP-bound token (no proof) => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'bearer valid bearer token => invalid_request',
      tokenKind: 'valid-bearer-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'DPoP token without proof => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'invalid token with dpop scheme => invalid_token',
      tokenKind: 'invalid-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.SIG_FAILURE,
        challenge: `DPoP error="invalid_token", error_description="${ERR_DESC.SIG_FAILURE}", algs="ES256"`,
      },
    },
    {
      name: 'malformed token with dpop scheme => invalid_token',
      tokenKind: 'malformed-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.INVALID_JWS,
        challenge: `DPoP error="invalid_token", error_description="${ERR_DESC.INVALID_JWS}", algs="ES256"`,
      },
    },
    {
      name: 'dpop scheme with unbound bearer token => invalid_token',
      tokenKind: 'valid-bearer-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.CNF_MISSING,
        challenge: `DPoP error="invalid_token", error_description="${ERR_DESC.CNF_MISSING}", algs="ES256"`,
      },
    },
    {
      name: 'invalid DPoP proof string => invalid_dpop_proof',
      tokenKind: 'valid-dpop-token',
      proofKind: 'invalid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_dpop_proof',
        errorClass: InvalidDpopProofError,
        // This case requires special handling as the message could be coming from `Jose` or our own error
        errorDescription: new RegExp(`${ERR_DESC.DPOP_PROOF_FAIL}|DPoP proof "ath" mismatch`),
        challenge: new RegExp(
          `DPoP error="invalid_dpop_proof", error_description="${ERR_DESC.DPOP_PROOF_FAIL}", algs="ES256"|DPoP error="invalid_dpop_proof", error_description="DPoP proof "ath" mismatch", algs="ES256"`
        ),
      },
    },
    {
      name: 'random auth scheme with proof => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'random_string',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'proof but no Authorization header => invalid_request',
      tokenKind: 'empty',
      proofKind: 'valid-proof',
      scheme: 'none',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'valid dpop token with proof => OK',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: { ok: true },
    },
    {
      name: 'unsupported scheme foo => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'unsupported_scheme',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
    {
      name: 'malformed DPoP scheme "DPoP dpop" => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'DPoP dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'DPoP algs="ES256"',
      },
    },
  ],
  disabled: [
    {
      name: 'bearer DPoP-bound token + proof => OK',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: { ok: true },
    },
    {
      name: 'bearer blank token + proof => verify_access_token_error',
      tokenKind: 'empty',
      proofKind: 'valid-proof',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'bearer invalid token => invalid_token',
      tokenKind: 'invalid-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: {
        statusCode: 401,
        code: 'verify_access_token_error',
        errorClass: VerifyAccessTokenError,
        errorDescription: ERR_DESC.SIG_FAILURE,
        challenge: `Bearer realm="api", error="invalid_token", error_description="${ERR_DESC.SIG_FAILURE}"`,
      },
    },
    {
      name: 'bearer DPoP-bound token (no proof) => OK',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: { ok: true },
    },
    {
      name: 'valid bearer token => OK',
      tokenKind: 'valid-bearer-token',
      proofKind: 'none',
      scheme: 'bearer',
      expect: { ok: true },
    },
    {
      name: 'dpop scheme rejected (no proof) => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'dpop invalid token + proof => invalid_request',
      tokenKind: 'invalid-token',
      proofKind: 'valid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'dpop token + invalid proof string => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'invalid-proof',
      scheme: 'dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'random auth scheme with proof => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'valid-proof',
      scheme: 'random_string',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'proof but no Authorization header => invalid_request',
      tokenKind: 'empty',
      proofKind: 'valid-proof',
      scheme: 'none',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'unsupported scheme foo => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'unsupported_scheme',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
    {
      name: 'malformed DPoP scheme "DPoP dpop" => invalid_request',
      tokenKind: 'valid-dpop-token',
      proofKind: 'none',
      scheme: 'DPoP dpop',
      expect: {
        statusCode: 400,
        code: 'invalid_request',
        errorClass: InvalidRequestError,
        errorDescription: '',
        challenge: 'Bearer realm="api"',
      },
    },
  ],
};

describe('Mode: "allowed"', () => {
  runScenarios(scenariosByMode['allowed'], 'allowed');
});

describe('Mode: "required"', () => {
  runScenarios(scenariosByMode['required'], 'required');
});

describe('Mode: "disabled"', () => {
  runScenarios(scenariosByMode['disabled'], 'disabled');
});

function domainFromIssuer(iss: string) {
  return iss.replace(/^https?:\/\//, '').replace(/\/+$/, '');
}

function getScenarioDescription(scenario: Scenario): string {
  return `${scenario.name}
===========================================================================================
  Request:
  \tauthorization: \`${scenario.scheme} <${scenario.tokenKind}>\`,
  \t${scenario.proofKind.toLowerCase() === 'none' ? '// dpop: ×' : `dpop: <${scenario.proofKind}>`},
  Expected:
  ${
    scenario.expect.ok
      ? `\tOK | 200`
      : `\t- ${scenario.expect.errorClass?.name}
        - ${scenario.expect.statusCode}
        - ${scenario.expect.code}
        -----------------------------------------------------------------------------------
        - ${scenario.expect.challenge?.toString().split(', DPoP ').join(',\n\t- DPoP ')}
        `
  }
  \n`;
}

function runScenarios(scenarios: Scenario[], mode: 'allowed' | 'required' | 'disabled') {
  for (const scenario of scenarios) {
    test(getScenarioDescription(scenario), async () => {
      const cnfJkt = scenario.tokenKind === 'valid-dpop-token' ? ecThumbprint : undefined;
      const accessToken = await signToken(scenario.tokenKind, { cnfJkt });
      const proof = await makeProof(scenario.proofKind, accessToken, 'GET', 'https://api/resource');

      const client = new ApiClient({
        domain: domainFromIssuer(issuer),
        audience,
        dpop: { mode },
      });

      if (scenario.expect.ok) {
        const payload = await client.verifyAccessToken({
          accessToken,
          scheme: scenario.scheme,
          dpopProof: proof,
          httpMethod: 'GET',
          httpUrl: 'https://api/resource',
        } as unknown as VerifyAccessTokenOptions);
        expect(payload).toBeDefined();
        return;
      }

      const err = await client
        .verifyAccessToken({
          accessToken,
          scheme: scenario.scheme,
          dpopProof: proof,
          httpMethod: 'GET',
          httpUrl: 'https://api/resource',
        } as unknown as VerifyAccessTokenOptions)
        .catch((e) => e);
      
      if (scenario.expect.errorClass) {
        expect(err).toBeInstanceOf(scenario.expect.errorClass);
      }
      expect(err.code).toBe(scenario.expect.code);
      expect(err.statusCode).toBe(scenario.expect.statusCode);

      if (scenario.expect.errorDescription instanceof RegExp) {
        expect(err.message).toMatch(scenario.expect.errorDescription);
      } else {
        expect(err.message).toBe(scenario.expect.errorDescription);
      }
      const challengeHeader = err.headers?.['www-authenticate'];
      const challengeString = challengeHeader?.join(', ');

      if (scenario.expect.challenge instanceof RegExp) {
        expect(challengeString).toMatch(scenario.expect.challenge);
      } else {
        expect(challengeString).toEqual(scenario.expect.challenge);
      }
    });
  }
}
