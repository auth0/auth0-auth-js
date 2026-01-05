import { beforeAll, describe, expect, test } from 'vitest';
import { createHash } from 'crypto';
import { calculateJwkThumbprint, generateKeyPair, exportJWK, SignJWT } from 'jose';

import {
  ALLOWED_DPOP_ALGORITHMS,
  DPOP_ERROR_MESSAGES,
  buildChallenges,
  verifyDpopProof,
  normalizeUrl,
} from './dpop-api.js';
import { InvalidDpopProofError, InvalidRequestError, VerifyAccessTokenError } from './errors.js';

let ecPrivateKey: CryptoKey;
let ecPublicJwk: Record<string, unknown>;
let rsaPrivateKey: CryptoKey;
let rsaPublicJwk: Record<string, unknown>;

beforeAll(async () => {
  const kp = await generateKeyPair('ES256');
  ecPrivateKey = kp.privateKey;
  ecPublicJwk = (await exportJWK(kp.publicKey)) as Record<string, unknown>;
  (ecPublicJwk as Record<string, unknown>).alg = 'ES256';

  const rsa = await generateKeyPair('RS256');
  rsaPrivateKey = rsa.privateKey;
  rsaPublicJwk = (await exportJWK(rsa.publicKey)) as Record<string, unknown>;
  (rsaPublicJwk as Record<string, unknown>).alg = 'RS256';
});

describe('buildChallenges', () => {
  test('"allowed" mode | returns bearer and dpop challenges', () => {
    const headers = buildChallenges('allowed', ALLOWED_DPOP_ALGORITHMS, {});
    expect(headers['www-authenticate']).toEqual(['Bearer realm="api"', 'DPoP algs="ES256"']);
  });

  test('"required" mode | returns only dpop challenge', () => {
    const headers = buildChallenges('required', ALLOWED_DPOP_ALGORITHMS, {});
    expect(headers['www-authenticate']).toEqual(['DPoP algs="ES256"']);
  });

  test('"disabled" mode | returns only bearer challenge', () => {
    const headers = buildChallenges('disabled', ALLOWED_DPOP_ALGORITHMS, {});
    expect(headers['www-authenticate']).toEqual(['Bearer realm="api"']);
  });

  test('"allowed" mode | with bearer error info', () => {
    const headers = buildChallenges('allowed', ALLOWED_DPOP_ALGORITHMS, {
      error: 'invalid_token',
      errorDescription: 'sigfail',
    });
    expect(headers['www-authenticate']?.[0]).toContain(
      'Bearer realm="api", error="invalid_token", error_description="sigfail"'
    );
    expect(headers['www-authenticate']?.[1]).toContain('DPoP algs="ES256"');
  });

  test('"allowed" mode | with dpop error info', () => {
    const headers = buildChallenges('allowed', ALLOWED_DPOP_ALGORITHMS, {
      dpopError: 'invalid_dpop_proof',
      dpopErrorDescription: 'bad dpop',
    });
    expect(headers['www-authenticate']?.[0]).toContain('Bearer realm="api"');
    expect(headers['www-authenticate']?.[1]).toContain(
      'DPoP error="invalid_dpop_proof", error_description="bad dpop", algs="ES256"'
    );
  });

  test('errors omitted when params empty', () => {
    const headers = buildChallenges('allowed', ALLOWED_DPOP_ALGORITHMS, {});
    const wwwAuthenticate = headers['www-authenticate'];
    expect(Array.isArray(wwwAuthenticate) && wwwAuthenticate.some((c: string) => c.includes('error='))).toBe(false);
  });
});

describe('verifyDpopProof', () => {
  const optionsBase = {
    accessToken: 'token',
    method: 'GET',
    url: 'https://api/resource',
    cnfJkt: '',
    iatOffset: 300,
    iatLeeway: 30,
    algorithms: ALLOWED_DPOP_ALGORITHMS,
  };

  test('valid proof passes', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: ecPublicJwk, alg: 'ES256' });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).resolves.toBeUndefined();
  });

  test('missing proof throws', async () => {
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt: 'thumb', proof: '' })).rejects.toBeInstanceOf(
      InvalidDpopProofError
    );
  });

  test('multiple proofs throws', async () => {
    const err = await verifyDpopProof({ ...optionsBase, cnfJkt: 'thumb', proof: 'one,two' }).catch((e) => e);
    expect(err).toBeInstanceOf(InvalidDpopProofError);
    expect(err.code).toBe('invalid_dpop_proof');
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe(DPOP_ERROR_MESSAGES.MULTIPLE_PROOFS);
  });

  test('missing htm throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, omitHtm: true });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.INVALID_HTM);
  });

  test('missing htu throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, omitHtu: true });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.INVALID_HTU);
  });

  test('missing ath throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, omitAth: true });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.INVALID_ATH);
  });

  test('missing iat throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, omitIat: true });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.INVALID_IAT);
  });

  test('missing jti throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, omitJti: true });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.INVALID_JTI);
  });

  test('non-numeric iat throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, iat: 'bad' as unknown as number });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.INVALID_IAT);
  });

  test('missing cnf throws', async () => {
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: ecPublicJwk });
    const err = await verifyDpopProof({ ...optionsBase, cnfJkt: undefined, proof }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.cause).toEqual({ code: 'dpop_binding_mismatch' });
  });

  test('htm mismatch throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, htm: 'POST' });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.HTM_MISMATCH);
  });

  test('htu mismatch throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, htu: 'https://api/other' });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.HTU_MISMATCH);
  });

  test('ath mismatch throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, ath: 'bad' });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.ATH_MISMATCH);
  });

  test('iat outside window throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, iat: Math.floor(Date.now() / 1000) - 10000 });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(DPOP_ERROR_MESSAGES.IAT_MISMATCH);
  });

  test('invalid alg throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(rsaPublicJwk);
    const proof = await makeProof({
      accessToken: optionsBase.accessToken,
      alg: 'RS256',
      jwk: rsaPublicJwk,
      privateKey: rsaPrivateKey,
    });
    await expect(
      verifyDpopProof({ ...optionsBase, cnfJkt, proof, algorithms: ['ES256'] })
    ).rejects.toBeInstanceOf(InvalidDpopProofError);
  });

  test('missing jwk in header throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeCustomProof({ accessToken: optionsBase.accessToken, omitJwk: true });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(
      // `Jose` may return `"jwk" (JSON Web Key) Header Parameter must be a JSON object`.
      new RegExp(
        `(${DPOP_ERROR_MESSAGES.MISSING_JWK}|"jwk" \\(JSON Web Key\\) Header Parameter must be a JSON object)`
      )
    );
  });

  test('private key in jwk throws', async () => {
    const jwkWithD = { ...ecPublicJwk, d: 'secret' };
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: jwkWithD });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toThrow(
      // `Jose` may return `Invalid keyData`.
      new RegExp(`(${DPOP_ERROR_MESSAGES.PRIVATE_KEY_MATERIAL}|Invalid keyData)`)
    );
  });

  test('cnf thumbprint mismatch throws', async () => {
    const cnfJkt = 'other-thumb';
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: ecPublicJwk });
    const err = await verifyDpopProof({ ...optionsBase, cnfJkt, proof }).catch((e) => e);
    expect(err).toBeInstanceOf(VerifyAccessTokenError);
    expect(err.cause).toEqual({ code: 'dpop_binding_mismatch' });
  });

  test('invalid request URL throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: ecPublicJwk });
    await expect(verifyDpopProof({ ...optionsBase, url: 'not-a-url', cnfJkt, proof })).rejects.toBeInstanceOf(
      InvalidRequestError
    );
  });

  test('invalid htu URL throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, htu: 'bad-url', jwk: ecPublicJwk });
    await expect(verifyDpopProof({ ...optionsBase, cnfJkt, proof })).rejects.toBeInstanceOf(InvalidDpopProofError);
  });

  test('request URL with protocol-like path throws', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: ecPublicJwk });
    await expect(
      verifyDpopProof({ ...optionsBase, url: 'https://api/https://evil.com', cnfJkt, proof })
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  test('request URL with empty path normalizes to "/"', async () => {
    const cnfJkt = await calculateJwkThumbprint(ecPublicJwk);
    const proof = await makeProof({ accessToken: optionsBase.accessToken, jwk: ecPublicJwk, htu: 'https://api/' });
    await expect(verifyDpopProof({ ...optionsBase, url: 'https://api', cnfJkt, proof })).resolves.toBeUndefined();
  });
});

describe('normalizeUrl', () => {
  test('removes query and fragment from URL (htu)', () => {
    const raw = 'https://api.example.com/resource?foo=bar#hash';
    const expected = 'https://api.example.com/resource';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('preserves trailing slash if present', () => {
    const raw = 'https://api.example.com/resource/?abc=def';
    const expected = 'https://api.example.com/resource/';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('preserves non-default port in normalized URL', () => {
    const raw = 'https://api.example.com:8443/resource?foo=bar';
    const expected = 'https://api.example.com:8443/resource';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('should not preserve username and password in URL (htu)', () => {
    const raw = 'https://user:pass@api.example.com/resource?foo=bar';
    const expected = 'https://api.example.com/resource';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('normalizes localhost with port and query/hash', () => {
    const raw = 'http://localhost:3000/path?debug=true#frag';
    const expected = 'http://localhost:3000/path';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('supports IP addresses as hosts', () => {
    const raw = 'http://127.0.0.1:4000/test?foo=bar';
    const expected = 'http://127.0.0.1:4000/test';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('throws InvalidRequestError if request URL is invalid', () => {
    const malformed = 'ht!tp:/broken-url';
    expect(() => normalizeUrl(malformed, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(malformed, 'request')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL);
  });

  test('throws InvalidProofError if proof htu is invalid', () => {
    const malformed = ':://foo.bar?x=1';
    expect(() => normalizeUrl(malformed, 'proof')).toThrow(InvalidDpopProofError);
    expect(() => normalizeUrl(malformed, 'proof')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTU_URL);
  });

  test('should return the same URL when already normalized', () => {
    const input = 'https://api.example.com/path';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('should normalize scheme and host casing', () => {
    const input = 'HTTPS://API.EXAMPLE.COM/path';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('should remove default port (443)', () => {
    const input = 'https://api.example.com:443/path';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('should normalize percent-encoding to uppercase', () => {
    const input = 'https://api.example.com/path%2fto%2fresource';
    const expected = 'https://api.example.com/path%2Fto%2Fresource';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('decodes unreserved percent-encodings (and keeps reserved encoded)', () => {
    const input = 'https://api.example.com/%7Euser/path%2Fwith%2Fslash';
    const expected = 'https://api.example.com/~user/path%2Fwith%2Fslash'; // ~ decoded, / kept encoded (uppercased)
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('should resolve dot segments in path', () => {
    const input = 'https://api.example.com/path/../resource/./file.txt';
    const expected = 'https://api.example.com/resource/file.txt';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('should strip query and fragment (request)', () => {
    const input = 'https://api.example.com/path?query=value#fragment';
    const expected = 'https://api.example.com/path';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('should normalize full complex URL with auth, port, dot segments, and fragment', () => {
    const input = 'HTTPS://USER:PASS@API.EXAMPLE.COM:443/path/../RESOURCE/./file.txt?query=value#fragment';
    const expected = 'https://api.example.com/RESOURCE/file.txt';
    const actual = normalizeUrl(input, 'request');
    expect(actual).toBe(expected);
  });

  test('host validation | rejects host with underscore (request)', () => {
    const input = 'https://bad_host.example/path';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL_HOST);
  });

  test('host validation | rejects host with underscore (proof)', () => {
    const input = 'https://bad_host.example/path';
    expect(() => normalizeUrl(input, 'proof')).toThrow(InvalidDpopProofError);
    expect(() => normalizeUrl(input, 'proof')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTU_URL_HOST);
  });

  test('host validation | accepts IPv6 literal host [::1] (request)', () => {
    const input = 'http://[::1]/path?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('http://[::1]/path');
  });

  test('host validation | accepts IPv6 literal host [::1] (proof)', () => {
    const input = 'http://[::1]/path?x=1#y';
    expect(normalizeUrl(input, 'proof')).toBe('http://[::1]/path');
  });

  test('host validation | rejects overlong port (6+ digits)', () => {
    const input = 'https://api.example.com:999999/path';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL);
  });

  test('host validation | accepts punycode hostnames', () => {
    const input = 'https://xn--bcher-kva.de/path';
    const expected = 'https://xn--bcher-kva.de/path';
    expect(normalizeUrl(input, 'request')).toBe(expected);
  });

  test('host validation | accepts trailing dot in hostname', () => {
    const input = 'https://example.com./x';
    const expected = 'https://example.com./x';
    expect(normalizeUrl(input, 'request')).toBe(expected);
  });

  test('host validation | accepts IPv6 literal with port (request)', () => {
    const input = 'http://[2001:db8::1]:8080/alpha?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('http://[2001:db8::1]:8080/alpha');
  });

  test('host validation | accepts IPv6 literal with port (proof)', () => {
    const input = 'http://[2001:db8::1]:3000/path?x=1#y';
    expect(normalizeUrl(input, 'proof')).toBe('http://[2001:db8::1]:3000/path');
  });

  test('host validation | rejects malformed IPv6 literal (missing closing bracket)', () => {
    const input = 'http://[2001:db8::1/path';
    // WHATWG URL will throw a TypeError; we map to generic InvalidRequestError
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL);
  });

  test('path checks | allows "//" sequence for request path', () => {
    const input = 'https://api.example.com//double/slash?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('https://api.example.com//double/slash');
  });

  test('path checks | allows "//" sequence for proof', () => {
    const input = 'https://api.example.com//double/slash?x=1#y';
    expect(normalizeUrl(input, 'proof')).toBe('https://api.example.com//double/slash');
  });

  test('path checks | rejects protocol-looking substring right after "/" in path (request)', () => {
    const input = 'https://api.example.com/https://evil.example.com/steal';
    expect(() => normalizeUrl(input, 'request')).toThrow(InvalidRequestError);
    expect(() => normalizeUrl(input, 'request')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTTP_URL_PATH);
  });

  test('path checks | does not apply the path protocol check to proof', () => {
    const input = 'https://api.example.com/https://evil.example.com/steal?x=1#y';
    const expected = 'https://api.example.com/https://evil.example.com/steal';
    expect(normalizeUrl(input, 'proof')).toBe(expected);
  });

  test('path checks | allows "//" inside request path', () => {
    const input = 'https://api.example.com/path//segment?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('https://api.example.com/path//segment');
  });

  test('malformed URLs and parser failures | throws generic InvalidProofError on URL parse failure (proof)', () => {
    const input = '::::://';
    expect(() => normalizeUrl(input, 'proof')).toThrow(InvalidDpopProofError);
    expect(() => normalizeUrl(input, 'proof')).toThrow(DPOP_ERROR_MESSAGES.INVALID_HTU_URL);
  });

  test('origin + pathname output shape | strips credentials (userinfo) by returning origin + pathname (request)', () => {
    const raw = 'https://user:pass@api.example.com/secure?x=1#frag';
    const expected = 'https://api.example.com/secure';
    expect(normalizeUrl(raw, 'request')).toBe(expected);
  });

  test('origin + pathname output shape | keeps non-default port and lowercases scheme/host', () => {
    const raw = 'HTTPS://API.EXAMPLE.COM:8443/A/Path?Q=1#F';
    const expected = 'https://api.example.com:8443/A/Path';
    expect(normalizeUrl(raw, 'proof')).toBe(expected);
  });

  test('scheme normalization | strips default port 80 for http', () => {
    const input = 'http://api.example.com:80/path?x=1#y';
    expect(normalizeUrl(input, 'request')).toBe('http://api.example.com/path');
  });

  test('IDN host | Unicode hostname is normalized to punycode', () => {
    const input = 'https://bücher.de/weg';
    // WHATWG URL serializes to punycode
    expect(normalizeUrl(input, 'proof')).toBe('https://xn--bcher-kva.de/weg');
  });

  test('percent-encoding | non-ASCII bytes remain encoded with uppercase hex', () => {
    const input = 'https://api.example.com/price/%e2%82%ac';
    const expected = 'https://api.example.com/price/%E2%82%AC';
    expect(normalizeUrl(input, 'request')).toBe(expected);
  });

  test('path semantics | encoded dot-segments collapse after decode', () => {
    const input = 'https://api.example.com/a/%2e%2e/b';
    const expected = 'https://api.example.com/b';
    expect(normalizeUrl(input, 'proof')).toBe(expected);
  });

  test('IPv4-mapped IPv6 | canonicalizes embedded IPv4 to hex groups', () => {
    const input = 'http://[::ffff:192.0.2.128]:3000/x';
    expect(normalizeUrl(input, 'proof')).toBe('http://[::ffff:c000:280]:3000/x');
  });
});

// Helper to create a valid DPoP proof JWT
async function makeProof(opts: {
  accessToken: string;
  method?: string;
  url?: string;
  jwk?: Record<string, unknown>;
  alg?: string;
  privateKey?: CryptoKey;
  ath?: string;
  htm?: string;
  htu?: string;
  iat?: number;
}) {
  const {
    accessToken,
    method = 'GET',
    url = 'https://api/resource',
    jwk = ecPublicJwk,
    alg = 'ES256',
    privateKey,
    ath,
    htm = method,
    htu = url,
    iat = Math.floor(Date.now() / 1000),
  } = opts;

  const hash = createHash('sha256').update(accessToken).digest();
  const encodedHash = hash.toString('base64url');

  const payload: Record<string, unknown> = {
    htm,
    htu,
    iat,
    jti: 'jti',
    ath: ath ?? encodedHash,
  };

  return new SignJWT(payload).setProtectedHeader({ alg, typ: 'dpop+jwt', jwk }).sign(privateKey ?? ecPrivateKey);
}

// Helper to create a custom DPoP proof JWT with options to omit claims/headers
async function makeCustomProof(opts: {
  accessToken: string;
  htm?: string;
  htu?: string;
  ath?: string | null;
  iat?: number;
  jti?: string;
  omitHtm?: boolean;
  omitHtu?: boolean;
  omitAth?: boolean;
  omitJwk?: boolean;
  omitIat?: boolean;
  omitJti?: boolean;
}) {
  const {
    accessToken,
    htm = 'GET',
    htu = 'https://api/resource',
    ath,
    iat = Math.floor(Date.now() / 1000),
    jti = 'jti',
    omitHtm,
    omitHtu,
    omitAth,
    omitJwk,
    omitIat,
    omitJti,
  } = opts;

  const hash = createHash('sha256').update(accessToken).digest();
  const encodedHash = hash.toString('base64url');

  const payload: Record<string, unknown> = {};
  if (!omitJti) payload.jti = jti;
  if (!omitIat) payload.iat = iat;
  if (!omitHtm) payload.htm = htm;
  if (!omitHtu) payload.htu = htu;
  if (!omitAth) payload.ath = ath ?? encodedHash;

  const header: import('jose').JWTHeaderParameters = { alg: 'ES256', typ: 'dpop+jwt' };
  if (!omitJwk) header.jwk = ecPublicJwk;

  return new SignJWT(payload).setProtectedHeader(header).sign(ecPrivateKey);
}
