import { describe, expect, test, afterEach, beforeEach, vi } from 'vitest';

// Dynamically import so each test suite gets a fresh module (and fresh cache)
let isFederatedDomain: typeof import('./domain-discovery.js').isFederatedDomain;

describe('isFederatedDomain', () => {
  beforeEach(async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    vi.resetModules();
    const mod = await import('./domain-discovery.js');
    isFederatedDomain = mod.isFederatedDomain;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const AUTH0_DOMAIN = 'test-tenant.auth0.com';
  const EMAIL_DOMAIN = 'acmecorp.com';

  function createMockFetch(status: number, body?: unknown, throwError = false): typeof fetch {
    return vi.fn(async () => {
      if (throwError) throw new Error('network error');
      return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => body,
      } as Response;
    });
  }

  test('returns true when 200 with matching OIDC issuer rel', async () => {
    const mockFetch = createMockFetch(200, {
      links: [{ rel: 'http://openid.net/specs/connect/1.0/issuer', href: 'https://test.auth0.com/' }],
    });

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(true);
  });

  test('returns false when 200 with no matching rel', async () => {
    const mockFetch = createMockFetch(200, {
      links: [{ rel: 'http://some-other-rel', href: 'https://test.auth0.com/' }],
    });

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
  });

  test('returns false when 200 with empty links array', async () => {
    const mockFetch = createMockFetch(200, { links: [] });

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
  });

  test('returns false on 404', async () => {
    const mockFetch = createMockFetch(404);

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
  });

  test('returns false on 403 (endpoint disabled)', async () => {
    const mockFetch = createMockFetch(403);

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
  });

  test('returns false and warns on 429', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mockFetch = createMockFetch(429);

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
    expect(warnSpy).toHaveBeenCalledWith('[Auth0] isFederatedDomain: rate limit hit (429)');
    warnSpy.mockRestore();
  });

  test('returns false on network error', async () => {
    const mockFetch = createMockFetch(0, undefined, true);

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
  });

  test('caches true results for 60 seconds', async () => {
    const mockFetch = createMockFetch(200, {
      links: [{ rel: 'http://openid.net/specs/connect/1.0/issuer', href: 'https://test.auth0.com/' }],
    });

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call uses cache
    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // After 60s cache expires
    vi.advanceTimersByTime(60_000);
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('caches false (404) results for 15 seconds', async () => {
    const mockFetch = createMockFetch(404);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call uses cache
    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(false);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // After 15s cache expires
    vi.advanceTimersByTime(15_000);
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('does not cache 200 with no matching rel', async () => {
    const mockFetch = createMockFetch(200, { links: [] });

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('does not cache 403', async () => {
    const mockFetch = createMockFetch(403);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('does not cache 429', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mockFetch = createMockFetch(429);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('does not cache network errors', async () => {
    const mockFetch = createMockFetch(0, undefined, true);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('normalizes email domain to lowercase', async () => {
    const mockFetch = createMockFetch(200, {
      links: [{ rel: 'http://openid.net/specs/connect/1.0/issuer', href: 'https://test.auth0.com/' }],
    });

    await isFederatedDomain(AUTH0_DOMAIN, 'ACMECORP.COM', { customFetch: mockFetch });

    const calls = (mockFetch as ReturnType<typeof vi.fn>).mock.calls;
    const url = calls[0]![0] as string;
    expect(url).toContain('acmecorp.com');
  });

  test('URL-encodes resource and rel params', async () => {
    const mockFetch = createMockFetch(200, { links: [] });

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });

    const calls = (mockFetch as ReturnType<typeof vi.fn>).mock.calls;
    const url = calls[0]![0] as string;
    expect(url).toContain(encodeURIComponent('urn:auth0:discovery:domain:acmecorp.com'));
    expect(url).toContain(encodeURIComponent('http://openid.net/specs/connect/1.0/issuer'));
  });

  test('uses customFetch when provided', async () => {
    const mockFetch = createMockFetch(200, { links: [] });

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalled();
  });

  test('applies telemetry headers when configured', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ links: [] }),
    })) as unknown as typeof fetch;

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, {
      customFetch: mockFetch,
      telemetry: { enabled: true, name: '@auth0/auth0-server-js', version: '1.0.0' },
    });

    const calls = (mockFetch as ReturnType<typeof vi.fn>).mock.calls;
    const calledInit = calls[0]![1] as RequestInit;
    const headers = new Headers(calledInit.headers);
    expect(headers.get('Auth0-Client')).toBeTruthy();
  });
});
