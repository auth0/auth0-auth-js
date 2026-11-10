import { expect, test } from 'vitest';
import { ApiClient } from '../../dist/index.js';
import { createTestAgent } from '../../dist/testing.js';
import { generateToken, jwks } from '../test-utils/tokens.js';

const DOMAIN = 'example.auth0.com';
const ISSUER = 'https://example.auth0.com/';
const DISCOVERY_URL = `${ISSUER}.well-known/openid-configuration`;
const JWKS_URL = `${ISSUER}.well-known/jwks.json`;
const AUDIENCE = 'https://api.example.com/';
const ORDERS_URL = 'https://api.example.com/orders';
const SID = 'Yx2b7Qd_Kp8mR3vT1nWc4A';
// The SHA-256 hash of the text `<agent URL>\n<SID>` for the default test agent and this SID, base64url-encoded,
// computed with another implementation.
const KEY = 'TCKalJy8Oz7hl1YTKAJt86LQcaiaLsYmFX-cLwiaJ4c';

test('verifies a signed-out Session end to end, without a network', async () => {
  const agent = await createTestAgent();
  const apiClient = new ApiClient({
    domain: DOMAIN,
    audience: AUDIENCE,
    poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
  });
  const sessionJwt = await agent.createSessionJwt({ aud: ISSUER, htm: 'POST', htu: ORDERS_URL, sid: SID });

  const result = await apiClient.verifyPoppyRequest({
    method: 'POST',
    url: ORDERS_URL,
    headers: { 'poppy-session': sessionJwt },
  });

  expect(result).toStrictEqual({
    poppy: {
      sessionId: SID,
      key: KEY,
      userId: 'usr_test',
      agent: { cimdUrl: agent.cimdUrl },
      state: 'signed_out',
      source: 'header',
    },
  });
});

test('verifies a signed-in Session end to end: the hash of the access token, and the token itself', async () => {
  const agent = await createTestAgent();
  // Auth0 is served by a `fetch` of the test, so that nothing reaches a network.
  const auth0Fetch: typeof fetch = async (input) => {
    const url = new URL(typeof input === 'string' ? input : 'href' in input ? input.href : input.url).href;
    if (url === DISCOVERY_URL) {
      return Response.json({ issuer: ISSUER, jwks_uri: JWKS_URL, token_endpoint: `${ISSUER}oauth/token` });
    }
    if (url === JWKS_URL) {
      return Response.json({ keys: jwks });
    }
    return new Response('Not found', { status: 404 });
  };
  const apiClient = new ApiClient({
    domain: DOMAIN,
    audience: AUDIENCE,
    customFetch: auth0Fetch,
    poppy: { verifySession: true, agentMetadata: { fetch: agent.fetch } },
  });
  const accessToken = await generateToken(DOMAIN, 'auth0|ana', AUDIENCE, undefined, undefined, undefined, {
    azp: agent.cimdUrl,
  });
  const sessionJwt = await agent.createSessionJwt({ aud: ISSUER, htm: 'POST', htu: ORDERS_URL, sid: SID, accessToken });

  const result = await apiClient.verifyPoppyRequest({
    method: 'POST',
    url: ORDERS_URL,
    headers: { 'poppy-session': sessionJwt, authorization: `Bearer ${accessToken}` },
  });

  expect(result.poppy).toStrictEqual({
    sessionId: SID,
    key: KEY,
    userId: 'usr_test',
    agent: { cimdUrl: agent.cimdUrl },
    state: 'signed_in',
    source: 'header',
  });
  expect(result.claims).toMatchObject({ sub: 'auth0|ana', iss: ISSUER, aud: AUDIENCE, azp: agent.cimdUrl });
});
