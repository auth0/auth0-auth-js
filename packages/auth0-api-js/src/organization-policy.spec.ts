import { expect, test, afterAll, beforeAll, afterEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { generateToken, jwks } from './test-utils/tokens.js';
import { ApiClient } from './api-client.js';
import {
  InvalidConfigurationError,
  MissingOrganizationError,
  OrganizationNotAllowedError,
} from './errors.js';

const domain = 'auth0.local';
const audience = '<audience>';
const mockOpenIdConfiguration = {
  issuer: `https://${domain}/`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
  token_endpoint: `https://${domain}/oauth/token`,
};

const server = setupServer(
  http.get(`https://${domain}/.well-known/openid-configuration`, () => HttpResponse.json(mockOpenIdConfiguration)),
  http.get(`https://${domain}/.well-known/jwks.json`, () => HttpResponse.json({ keys: jwks }))
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

test('constructor throws InvalidConfigurationError when organizationId set without required policy', () => {
  expect(() => new ApiClient({ domain, audience, organizationId: 'org_123' })).toThrow(InvalidConfigurationError);
  expect(() => new ApiClient({ domain, audience, organizationPolicy: 'allow', organizationId: 'org_123' })).toThrow(
    InvalidConfigurationError
  );
});

test("'required' + missing org_id throws MissingOrganizationError (401)", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required' });
  const accessToken = await generateToken(domain, '<sub>', audience);
  const err = await apiClient.verifyAccessToken({ accessToken }).catch((e) => e);
  expect(err).toBeInstanceOf(MissingOrganizationError);
  expect(err.code).toBe('missing_organization');
  expect(err.statusCode).toBe(401);
});

test("'required' with allowlist + org_id not in list throws OrganizationNotAllowedError (401)", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: ['org_allowed'] });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_other',
  });
  const err = await apiClient.verifyAccessToken({ accessToken }).catch((e) => e);
  expect(err).toBeInstanceOf(OrganizationNotAllowedError);
  expect(err.code).toBe('organization_not_allowed');
  expect(err.statusCode).toBe(401);
});

test("'required' with matching org_id passes", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: 'org_allowed' });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_allowed',
  });
  const payload = await apiClient.verifyAccessToken({ accessToken });
  expect(payload.org_id).toBe('org_allowed');
});

test("string allowlist coerced to one-element list (matching org_id passes)", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: 'org_solo' });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_solo',
  });
  await expect(apiClient.verifyAccessToken({ accessToken })).resolves.toBeDefined();
});

test("'required' + org_id present, no allowlist passes", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required' });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_any',
  });
  await expect(apiClient.verifyAccessToken({ accessToken })).resolves.toBeDefined();
});

test("'allow' default: token with no org_id verifies unchanged", async () => {
  const apiClient = new ApiClient({ domain, audience }); // no policy => 'allow'
  const accessToken = await generateToken(domain, '<sub>', audience);
  await expect(apiClient.verifyAccessToken({ accessToken })).resolves.toBeDefined();
});

test("'allow' default: token WITH org_id passes through without enforcement", async () => {
  const apiClient = new ApiClient({ domain, audience });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_any',
  });
  const payload = await apiClient.verifyAccessToken({ accessToken });
  expect(payload.org_id).toBe('org_any');
});

test("organizationPolicy: 'allow' explicit: passes when org_id is absent", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'allow' });
  const accessToken = await generateToken(domain, '<sub>', audience);
  await expect(apiClient.verifyAccessToken({ accessToken })).resolves.toBeDefined();
});

test("'required' with multi-element array allowlist: org_id matching second element passes", async () => {
  const apiClient = new ApiClient({
    domain,
    audience,
    organizationPolicy: 'required',
    organizationId: ['org_first', 'org_second', 'org_third'],
  });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_second',
  });
  const payload = await apiClient.verifyAccessToken({ accessToken });
  expect(payload.org_id).toBe('org_second');
});

test("'required' with multi-element array allowlist: org_id not in list throws OrganizationNotAllowedError", async () => {
  const apiClient = new ApiClient({
    domain,
    audience,
    organizationPolicy: 'required',
    organizationId: ['org_a', 'org_b'],
  });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_c',
  });
  const err = await apiClient.verifyAccessToken({ accessToken }).catch((e) => e);
  expect(err).toBeInstanceOf(OrganizationNotAllowedError);
  expect(err.code).toBe('organization_not_allowed');
  expect(err.statusCode).toBe(401);
});

test("'required': whitespace-only org_id treated as missing, throws MissingOrganizationError", async () => {
  const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required' });
  const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: '   ',
  });
  const err = await apiClient.verifyAccessToken({ accessToken }).catch((e) => e);
  expect(err).toBeInstanceOf(MissingOrganizationError);
  expect(err.code).toBe('missing_organization');
  expect(err.statusCode).toBe(401);
});

test.each(['Required', 'none', '', null, 1, true])(
  'constructor throws InvalidConfigurationError for invalid organizationPolicy %j',
  (value) => {
    expect(() => new ApiClient({ domain, audience, organizationPolicy: value as never })).toThrow(
      InvalidConfigurationError
    );
  }
);

test.each([
  [[]],
  [''],
  ['   '],
  [' org_a '],
  [[123]],
  [['']],
  [['org_ok', '']],
  [['org_ok', '   ']],
  [['org_ok', ' org_b']],
  [null],
  [123],
  [{}],
])('constructor throws InvalidConfigurationError for invalid organizationId %j', (value) => {
  expect(
    () => new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: value as never })
  ).toThrow(InvalidConfigurationError);
});

test.each([[123], [['org_a', 'org_b']]])(
  'non-string org_id claim %j is treated as missing',
  async (orgId) => {
    const apiClient = new ApiClient({ domain, audience, organizationPolicy: 'required' });
    const accessToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
      org_id: orgId,
    });
    const err = await apiClient.verifyAccessToken({ accessToken }).catch((e) => e);
    expect(err).toBeInstanceOf(MissingOrganizationError);
    expect(err.statusCode).toBe(401);
  }
);

test('organization errors report error="invalid_token" on the wire while keeping a specific SDK code', async () => {
  const missing = new ApiClient({ domain, audience, organizationPolicy: 'required' });
  const noOrgToken = await generateToken(domain, '<sub>', audience);
  const missingErr = await missing.verifyAccessToken({ accessToken: noOrgToken }).catch((e) => e);
  const notAllowed = new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: 'org_a' });
  const otherOrgToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_b',
  });
  const notAllowedErr = await notAllowed.verifyAccessToken({ accessToken: otherOrgToken }).catch((e) => e);

  for (const [err, sdkCode] of [
    [missingErr, 'missing_organization'],
    [notAllowedErr, 'organization_not_allowed'],
  ] as const) {
    // dpop.mode defaults to 'allowed', so both a Bearer and a DPoP challenge are offered
    // and the error belongs on the Bearer one.
    const challenges = err.headers['www-authenticate'] as string[];
    expect(challenges).toHaveLength(2);
    const header = challenges.find((challenge) => challenge.startsWith('Bearer '))!;
    const dpopChallenge = challenges.find((challenge) => challenge.startsWith('DPoP '))!;
    expect(header).toBeDefined();
    expect(dpopChallenge).toBeDefined();
    expect(dpopChallenge).not.toContain('error=');

    // RFC 6750 section 3.1 allows only invalid_request, invalid_token and
    // insufficient_scope here, so the specific SDK code must reach neither the
    // error parameter nor the description.
    expect(header).toContain('realm="api"');
    expect(header).toContain('error="invalid_token"');
    expect(header).not.toContain(sdkCode);
    expect(err.code).toBe(sdkCode);

    // RFC 6750 forbids a double quote inside the quoted error_description, so the
    // challenge carries exactly three quoted values and no others.
    expect((header.match(/"/g) ?? []).length).toBe(6);
    const description = /error_description="([^"]*)"/.exec(header);
    expect(description).not.toBeNull();
    expect(description![1]).toContain('(org_id)');
  }

  // Neither the rejected organization nor the allowlist is disclosed to the caller.
  const notAllowedChallenges = (notAllowedErr.headers['www-authenticate'] as string[]).join(', ');
  expect(notAllowedErr.message).not.toContain('org_b');
  expect(notAllowedErr.message).not.toContain('org_a');
  expect(notAllowedChallenges).not.toContain('org_b');
  expect(notAllowedChallenges).not.toContain('org_a');
});

test('DPoP mode: organization policy is enforced before proof validation and the DPoP challenge carries invalid_token', async () => {
  const apiClient = new ApiClient({
    domain,
    audience,
    organizationPolicy: 'required',
    dpop: { mode: 'required' },
  });
  const accessToken = await generateToken(domain, '<sub>', audience);
  const err = await apiClient
    .verifyAccessToken({ accessToken, scheme: 'dpop', dpopProof: 'x', httpMethod: 'GET', httpUrl: 'https://api.local/' })
    .catch((e) => e);

  // An invalid proof is supplied, so reaching MissingOrganizationError proves the
  // organization check runs ahead of proof validation.
  expect(err).toBeInstanceOf(MissingOrganizationError);
  expect(err.statusCode).toBe(401);

  const challenges = err.headers['www-authenticate'] as string[];
  expect(challenges).toHaveLength(1);
  expect(challenges[0]).toMatch(/^DPoP /);
  expect(challenges[0]).toContain('error="invalid_token"');
  expect(challenges[0]).not.toContain('missing_organization');
});

test('valid organization configurations construct without throwing', () => {
  expect(
    () => new ApiClient({ domain, audience, organizationPolicy: undefined, organizationId: undefined })
  ).not.toThrow();
  expect(() => new ApiClient({ domain, audience, organizationPolicy: 'allow' })).not.toThrow();
  expect(() => new ApiClient({ domain, audience, organizationPolicy: 'required' })).not.toThrow();
  expect(() => new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: 'org_a' })).not.toThrow();
  expect(
    () => new ApiClient({ domain, audience, organizationPolicy: 'required', organizationId: ['org_a', 'org_b'] })
  ).not.toThrow();
});

test('mutating the caller options after construction cannot widen or disable enforcement', async () => {
  const options = {
    domain,
    audience,
    organizationPolicy: 'required' as const,
    organizationId: ['org_allowed'],
  };
  const apiClient = new ApiClient(options);

  options.organizationId.push('org_other');
  (options as { organizationPolicy: string }).organizationPolicy = 'allow';

  const otherOrgToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_other',
  });
  const err = await apiClient.verifyAccessToken({ accessToken: otherOrgToken }).catch((e) => e);
  expect(err).toBeInstanceOf(OrganizationNotAllowedError);

  const noOrgToken = await generateToken(domain, '<sub>', audience);
  const missingErr = await apiClient.verifyAccessToken({ accessToken: noOrgToken }).catch((e) => e);
  expect(missingErr).toBeInstanceOf(MissingOrganizationError);

  const allowedToken = await generateToken(domain, '<sub>', audience, undefined, undefined, undefined, {
    org_id: 'org_allowed',
  });
  await expect(apiClient.verifyAccessToken({ accessToken: allowedToken })).resolves.toBeDefined();
});
