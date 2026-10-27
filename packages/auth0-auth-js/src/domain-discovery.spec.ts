import { describe, expect, test, afterEach, beforeEach, vi } from 'vitest';
import { HTTP_TIMEOUT_MESSAGE } from './request-fetch.js';

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

  test('returns true on 200', async () => {
    const mockFetch = createMockFetch(200);

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(true);
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
    const mockFetch = createMockFetch(200);

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
    const mockFetch = createMockFetch(200);

    await isFederatedDomain(AUTH0_DOMAIN, 'ACMECORP.COM', { customFetch: mockFetch });

    const calls = (mockFetch as ReturnType<typeof vi.fn>).mock.calls;
    const url = calls[0]![0] as string;
    expect(url).toContain('acmecorp.com');
  });

  test('strips https:// scheme prefix from auth0Domain', async () => {
    const mockFetch = createMockFetch(200);

    const result = await isFederatedDomain(`https://${AUTH0_DOMAIN}`, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(true);
    const url = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string;
    expect(url).toContain(`https://${AUTH0_DOMAIN}/`);
    expect(url).not.toContain('https://https://');
  });

  test('strips http:// scheme prefix from auth0Domain', async () => {
    const mockFetch = createMockFetch(200);

    const result = await isFederatedDomain(`http://${AUTH0_DOMAIN}`, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(result).toBe(true);
    const url = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0]![0] as string;
    expect(url).toContain(`https://${AUTH0_DOMAIN}/`);
  });

  test('URL-encodes resource and rel params', async () => {
    const mockFetch = createMockFetch(200);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });

    const calls = (mockFetch as ReturnType<typeof vi.fn>).mock.calls;
    const url = calls[0]![0] as string;
    expect(url).toContain(encodeURIComponent('urn:auth0:discovery:domain:acmecorp.com'));
    expect(url).toContain(encodeURIComponent('http://openid.net/specs/connect/1.0/issuer'));
  });

  test('uses customFetch when provided', async () => {
    const mockFetch = createMockFetch(200);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });
    expect(mockFetch).toHaveBeenCalled();
  });

  test('applies telemetry headers when configured', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
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

  test('returns false when the lookup is slower than httpTimeout, and does not cache it', async () => {
    // AbortSignal.timeout runs on real timers.
    vi.useRealTimers();
    // Answers only when aborted, as a real fetch does.
    const hangingFetch = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
        })
    ) as unknown as typeof fetch;
    const started = Date.now();

    const result = await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: hangingFetch, httpTimeout: 50 });

    expect(result).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
    const calledInit = (hangingFetch as ReturnType<typeof vi.fn>).mock.calls[0]![1] as RequestInit;
    expect(calledInit.signal).toBeInstanceOf(AbortSignal);

    const fastFetch = createMockFetch(200);
    expect(await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: fastFetch, httpTimeout: 50 })).toBe(true);
  });

  test('passes no signal when httpTimeout is not set', async () => {
    const mockFetch = createMockFetch(200);

    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });

    const calledInit = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0]![1] as RequestInit | undefined;
    expect(calledInit?.signal).toBeUndefined();
  });

  test.each([1500.5, 0, NaN, -1, '1000'])(
    'throws a TypeError for httpTimeout %s, without a request or a cached result',
    async (value) => {
      const mockFetch = createMockFetch(200);

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch, httpTimeout: value as number })
      ).rejects.toThrow(new TypeError(HTTP_TIMEOUT_MESSAGE));
      expect(mockFetch).not.toHaveBeenCalled();

      // Nothing was cached: a valid call still makes the request.
      expect(await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch })).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    }
  );

  test('throws for an invalid httpTimeout even when the result is cached', async () => {
    const mockFetch = createMockFetch(200);
    await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch });

    await expect(
      isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch, httpTimeout: 1500.5 })
    ).rejects.toThrow(TypeError);
  });

  test('a valid httpTimeout behaves as before', async () => {
    const mockFetch = createMockFetch(200);

    expect(await isFederatedDomain(AUTH0_DOMAIN, EMAIL_DOMAIN, { customFetch: mockFetch, httpTimeout: 1500 })).toBe(
      true
    );
  });
});
