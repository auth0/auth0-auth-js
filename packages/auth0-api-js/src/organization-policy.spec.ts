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
