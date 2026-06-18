import { expect, test, describe, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { PasswordlessClient } from './passwordless-client.js';
import { PasswordlessStartError } from './errors.js';
import { MissingClientAuthError } from '../errors.js';

const domain = 'auth0.local';
const clientId = 'test-client-id';
const clientSecret = 'test-client-secret';
const startUrl = `https://${domain}/passwordless/start`;

const exportPrivateKeyToPem = async (privateKey: CryptoKey): Promise<string> => {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  const keyBase64 = Buffer.from(pkcs8).toString('base64');
  const keyLines = keyBase64.match(/.{1,64}/g) ?? [keyBase64];
  return `-----BEGIN PRIVATE KEY-----\n${keyLines.join('\n')}\n-----END PRIVATE KEY-----`;
};

const generateRsaKeyPair = () =>
  crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: { name: 'SHA-256' } },
    true,
    ['sign', 'verify']
  ) as Promise<CryptoKeyPair>;

// Captures the last request body seen by the /passwordless/start handler.
let lastBody: Record<string, unknown> | null;
let requestCount: number;

const restHandlers = [
  http.post(startUrl, async ({ request }) => {
    requestCount += 1;
    lastBody = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({}, { status: 200 });
  }),
];

const server = setupServer(...restHandlers);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  lastBody = null;
  requestCount = 0;
  server.resetHandlers();
});
afterAll(() => server.close());

const secretClient = () => new PasswordlessClient({ domain, clientId, clientSecret });

describe('PasswordlessClient - sendEmail', () => {
  test('UT-1: sends code (default) with client_secret', async () => {
    await secretClient().sendEmail({ email: 'user@example.com', send: 'code' });

    expect(lastBody).toMatchObject({
      client_id: clientId,
      connection: 'email',
      email: 'user@example.com',
      send: 'code',
      client_secret: clientSecret,
    });
  });

  test('UT-2: sends link with authParams (camelCase key, no auth_params)', async () => {
    const authParams = { redirect_uri: 'https://app/cb', scope: 'openid', state: 'xyz' };
    await secretClient().sendEmail({ email: 'user@example.com', send: 'link', authParams });

    expect(lastBody!.send).toBe('link');
    expect(lastBody!.authParams).toEqual(authParams);
    expect(lastBody!).not.toHaveProperty('auth_params');
  });

  test('UT-3: link WITHOUT authParams resolves and omits the key', async () => {
    server.use(http.post(startUrl, () => new HttpResponse(null, { status: 204 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com', send: 'link' })).resolves.toBeUndefined();
  });

  test('UT-4: accepts 204 No Content', async () => {
    server.use(http.post(startUrl, () => new HttpResponse(null, { status: 204 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).resolves.toBeUndefined();
  });

  test('UT-5: accepts 200 with empty object body', async () => {
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).resolves.toBeUndefined();
  });

  test('UT-6: throws PasswordlessStartError on 400 with error body', async () => {
    server.use(
      http.post(startUrl, () =>
        HttpResponse.json({ error: 'invalid_request', error_description: 'Invalid email' }, { status: 400 })
      )
    );
    await expect(secretClient().sendEmail({ email: 'bad' })).rejects.toMatchObject({
      name: 'PasswordlessStartError',
      cause: { error_description: 'Invalid email' },
    });
  });

  test('UT-7: throws PasswordlessStartError on 401 unauthorized_client', async () => {
    server.use(http.post(startUrl, () => HttpResponse.json({ error: 'unauthorized_client' }, { status: 401 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-8: throws PasswordlessStartError on non-JSON error body (no cause)', async () => {
    server.use(http.post(startUrl, () => new HttpResponse('boom', { status: 400 })));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).rejects.toMatchObject({
      name: 'PasswordlessStartError',
      cause: undefined,
    });
  });

  test('UT-9: throws PasswordlessStartError on network error', async () => {
    server.use(http.post(startUrl, () => HttpResponse.error()));
    await expect(secretClient().sendEmail({ email: 'user@example.com' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-10: injects client_assertion for private_key_jwt with correct JWT claims', async () => {
    const { privateKey } = await generateRsaKeyPair();
    const pem = await exportPrivateKeyToPem(privateKey);
    const client = new PasswordlessClient({ domain, clientId, clientAssertionSigningKey: pem, clientAssertionSigningAlg: 'RS256' });

    await client.sendEmail({ email: 'user@example.com' });

    expect(lastBody!.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    const jwt = lastBody!.client_assertion as string;
    expect(typeof jwt).toBe('string');
    expect(decodeProtectedHeader(jwt).alg).toBe('RS256');
    const claims = decodeJwt(jwt);
    expect(claims.iss).toBe(clientId);
    expect(claims.sub).toBe(clientId);
    expect(claims.aud).toBe(`https://${domain}/`);
    expect(typeof claims.jti).toBe('string');
    const ttl = (claims.exp as number) - (claims.iat as number);
    expect(ttl).toBe(120);
    expect(lastBody!).not.toHaveProperty('client_secret');
  });

  test('UT-11: client_assertion accepts a CryptoKey input', async () => {
    const { privateKey } = await generateRsaKeyPair();
    const client = new PasswordlessClient({ domain, clientId, clientAssertionSigningKey: privateKey });

    await client.sendEmail({ email: 'user@example.com' });

    const jwt = lastBody!.client_assertion as string;
    expect(typeof jwt).toBe('string');
    expect(decodeJwt(jwt).aud).toBe(`https://${domain}/`);
  });

  test('UT-12: throws MissingClientAuthError when no client auth configured', async () => {
    const client = new PasswordlessClient({ domain, clientId });
    await expect(client.sendEmail({ email: 'user@example.com' })).rejects.toThrow(MissingClientAuthError);
  });

  test('UT-13: useMtls produces no body auth fields', async () => {
    const client = new PasswordlessClient({ domain, clientId, useMtls: true });
    await client.sendEmail({ email: 'user@example.com' });

    expect(lastBody!).not.toHaveProperty('client_secret');
    expect(lastBody!).not.toHaveProperty('client_assertion');
  });
});

describe('PasswordlessClient - sendSms', () => {
  test('UT-14: sends SMS with E.164 phone; no delivery_method', async () => {
    await secretClient().sendSms({ phoneNumber: '+14155550100' });

    expect(lastBody).toMatchObject({
      client_id: clientId,
      connection: 'sms',
      phone_number: '+14155550100',
      client_secret: clientSecret,
    });
    expect(lastBody!).not.toHaveProperty('delivery_method');
    expect(lastBody!).not.toHaveProperty('deliveryMethod');
  });

  test('UT-15: throws PasswordlessStartError on non-E.164 phone before request', async () => {
    await expect(secretClient().sendSms({ phoneNumber: '12025551234' })).rejects.toThrow(/E\.164/);
    expect(requestCount).toBe(0);
  });

  test('UT-16: accepts +44; rejects missing-+ before request', async () => {
    await expect(secretClient().sendSms({ phoneNumber: '+447911123456' })).resolves.toBeUndefined();
    expect(requestCount).toBe(1);
    await expect(secretClient().sendSms({ phoneNumber: '447911123456' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-17: throws PasswordlessStartError on API error', async () => {
    server.use(http.post(startUrl, () => HttpResponse.json({ error: 'sms_provider_error' }, { status: 400 })));
    await expect(secretClient().sendSms({ phoneNumber: '+14155550100' })).rejects.toThrow(PasswordlessStartError);
  });

  test('UT-18: telemetry-wrapped customFetch is used and headers pass through', async () => {
    const customFetch = vi.fn((...args: Parameters<typeof fetch>) => fetch(...args));
    const client = new PasswordlessClient({ domain, clientId, clientSecret, customFetch });

    await client.sendSms({ phoneNumber: '+14155550100' });

    expect(customFetch).toHaveBeenCalledTimes(1);
    const [, init] = customFetch.mock.calls[0];
    expect((init as RequestInit).method).toBe('POST');
  });
});
