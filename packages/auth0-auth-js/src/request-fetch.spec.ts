import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { createCapturingFetch, composeRequestFetch, combineSignals } from './request-fetch.js';
import { getTelemetryConfig } from './telemetry.js';
import type { RequestOptions } from './types.js';

const server = setupServer(
  http.post('https://auth0.local/custom/token', () =>
    HttpResponse.json({ access_token: 'tok123', token_type: 'Bearer', expires_in: 3600 })
  )
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
beforeEach(() => server.resetHandlers());

describe('createCapturingFetch', () => {
  describe('types', () => {
    it('returns object with getCapturedResponse method', () => {
      const cf = createCapturingFetch(fetch);
      expect(typeof cf).toBe('function');
      expect(typeof cf.getCapturedResponse).toBe('function');
    });
  });

  describe('capture behavior', () => {
    it('stores cloned response — caller gets fresh body', async () => {
      const cf = createCapturingFetch(fetch);
      await cf('https://auth0.local/custom/token', { method: 'POST' });
      const captured = cf.getCapturedResponse();

      expect(captured).toBeInstanceOf(Response);
      expect(captured!.bodyUsed).toBe(false);
      const body = await captured!.json();
      expect(body).toHaveProperty('access_token');
    });

    it('two instances do not share state', async () => {
      const cf1 = createCapturingFetch(fetch);
      const cf2 = createCapturingFetch(fetch);
      await cf1('https://auth0.local/custom/token', { method: 'POST' });

      expect(cf1.getCapturedResponse()).toBeInstanceOf(Response);
      expect(cf2.getCapturedResponse()).toBeUndefined();
    });

    it('getCapturedResponse returns undefined before first call', () => {
      const cf = createCapturingFetch(fetch);
      expect(cf.getCapturedResponse()).toBeUndefined();
    });

    it('cloned body is readable after wrapper returns', async () => {
      const cf = createCapturingFetch(fetch);
      const originalResponse = await cf('https://auth0.local/custom/token', { method: 'POST' });

      // Consume original
      await originalResponse.json();
      const captured = cf.getCapturedResponse()!;

      expect(originalResponse.bodyUsed).toBe(true);
      expect(captured.bodyUsed).toBe(false);
      const clonedBody = await captured.json();
      expect(clonedBody.access_token).toBe('tok123');
    });
  });

  describe('negative cases', () => {
    it('getCapturedResponse returns undefined before any fetch call', () => {
      const cf = createCapturingFetch(fetch);
      expect(cf.getCapturedResponse()).toBeUndefined();
    });
  });
});

describe('composeRequestFetch', () => {
  describe('reserved header filtering', () => {
    it('drops Authorization header (case-insensitive)', async () => {
      const capturedHeaders: Record<string, string> = {};
      const stubBaseFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.headers) {
          const headers = new Headers(init.headers);
          headers.forEach((value, key) => {
            capturedHeaders[key.toLowerCase()] = value;
          });
        }
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const telemetryConfig = getTelemetryConfig();
      const requestOptions: RequestOptions = {
        headers: {
          'Authorization': 'attacker-value',
          'authorization': 'attacker-value-2',
          'X-Custom': 'ok',
        },
      };

      const composedFetch = composeRequestFetch(stubBaseFetch, requestOptions, telemetryConfig);
      await composedFetch('https://example.com/api', { method: 'POST' });

      // Authorization headers should be dropped (case-insensitive)
      expect(capturedHeaders['authorization']).toBeUndefined();
      expect(capturedHeaders['Authorization']).toBeUndefined();
      // Custom headers should be preserved
      expect(capturedHeaders['x-custom']).toBe('ok');
    });

    it('drops Auth0-Client header (case-insensitive)', async () => {
      const capturedHeaders: Record<string, string> = {};
      const stubBaseFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.headers) {
          const headers = new Headers(init.headers);
          headers.forEach((value, key) => {
            capturedHeaders[key.toLowerCase()] = value;
          });
        }
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const telemetryConfig = getTelemetryConfig();
      const requestOptions: RequestOptions = {
        headers: {
          'Auth0-Client': 'attacker-client',
          'auth0-client': 'attacker-client-2',
          'X-Custom': 'ok',
        },
      };

      const composedFetch = composeRequestFetch(stubBaseFetch, requestOptions, telemetryConfig);
      await composedFetch('https://example.com/api', { method: 'POST' });

      // Auth0-Client headers should be dropped (case-insensitive)
      expect(capturedHeaders['auth0-client']).not.toBe('attacker-client');
      expect(capturedHeaders['auth0-client']).not.toBe('attacker-client-2');
      // Custom headers should be preserved
      expect(capturedHeaders['x-custom']).toBe('ok');
    });

    it('preserves non-reserved headers', async () => {
      const capturedHeaders: Record<string, string> = {};
      const stubBaseFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.headers) {
          const headers = new Headers(init.headers);
          headers.forEach((value, key) => {
            capturedHeaders[key.toLowerCase()] = value;
          });
        }
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const telemetryConfig = getTelemetryConfig();
      const requestOptions: RequestOptions = {
        headers: {
          'X-Custom-Header': 'custom-value',
          'Content-Type': 'application/json',
          'X-Request-ID': 'req-123',
        },
      };

      const composedFetch = composeRequestFetch(stubBaseFetch, requestOptions, telemetryConfig);
      await composedFetch('https://example.com/api', { method: 'POST' });

      expect(capturedHeaders['x-custom-header']).toBe('custom-value');
      expect(capturedHeaders['content-type']).toBe('application/json');
      expect(capturedHeaders['x-request-id']).toBe('req-123');
    });
  });
});

describe('combineSignals', () => {
  let originalAny: typeof AbortSignal.any;
  beforeEach(() => {
    originalAny = AbortSignal.any;
  });
  afterEach(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = originalAny;
  });

  it('returns combined signal when both present and AbortSignal.any is undefined (fallback path)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = undefined;

    const callerController = new AbortController();
    const initController = new AbortController();

    const { signal, cleanup } = combineSignals(callerController.signal, initController.signal);

    expect(signal).toBeDefined();
    expect(signal).not.toBe(callerController.signal);
    expect(signal).not.toBe(initController.signal);
    expect(cleanup).toBeInstanceOf(Function);

    // Abort caller signal → combined signal aborts with caller's reason
    callerController.abort('caller-reason');
    expect(signal!.aborted).toBe(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((signal as any).reason).toBe('caller-reason');

    cleanup!();
  });

  it('propagates init signal abort with init reason (fallback path)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = undefined;

    const callerController = new AbortController();
    const initController = new AbortController();

    const { signal, cleanup } = combineSignals(callerController.signal, initController.signal);

    // Abort init signal → combined signal aborts with init's reason
    initController.abort('init-reason');
    expect(signal!.aborted).toBe(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((signal as any).reason).toBe('init-reason');

    cleanup!();
  });

  it('detaches listeners from non-firing source on first abort (fallback path)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = undefined;

    const callerController = new AbortController();
    const initController = new AbortController();

    const removeEventListenerSpy = vi.spyOn(initController.signal, 'removeEventListener');

    const { cleanup } = combineSignals(callerController.signal, initController.signal);

    // Abort caller → init listener should be removed
    callerController.abort();
    expect(removeEventListenerSpy).toHaveBeenCalledWith('abort', expect.any(Function));

    cleanup!();
  });

  it('short-circuits when caller signal is already aborted (fallback path)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = undefined;

    const callerSignal = AbortSignal.abort('already-aborted');
    const initController = new AbortController();

    const addEventListenerSpy = vi.spyOn(initController.signal, 'addEventListener');

    const { signal: combinedSignal, cleanup } = combineSignals(callerSignal, initController.signal);

    expect(combinedSignal!.aborted).toBe(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((combinedSignal as any).reason).toBe('already-aborted');
    expect(cleanup).toBeUndefined();
    expect(addEventListenerSpy).not.toHaveBeenCalled();
  });

  it('short-circuits when init signal is already aborted (fallback path)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = undefined;

    const callerController = new AbortController();
    const initSignal = AbortSignal.abort('init-aborted');

    const addEventListenerSpy = vi.spyOn(callerController.signal, 'addEventListener');

    const { signal: combinedSignal, cleanup } = combineSignals(callerController.signal, initSignal);

    expect(combinedSignal!.aborted).toBe(true);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((combinedSignal as any).reason).toBe('init-aborted');
    expect(cleanup).toBeUndefined();
    expect(addEventListenerSpy).not.toHaveBeenCalled();
  });

  it('cleanup after normal completion does not throw (fallback path)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (AbortSignal as any).any = undefined;

    const callerController = new AbortController();
    const initController = new AbortController();

    const { signal, cleanup } = combineSignals(callerController.signal, initController.signal);

    expect(signal).toBeDefined();
    expect(() => cleanup!()).not.toThrow();
  });

  it('uses native AbortSignal.any when available (no cleanup)', () => {
    // Native AbortSignal.any is present by default in Node 20+
    const callerController = new AbortController();
    const initController = new AbortController();

    const { signal, cleanup } = combineSignals(callerController.signal, initController.signal);

    expect(signal).toBeDefined();
    expect(cleanup).toBeUndefined();
  });

  it('returns caller signal when init is null', () => {
    const callerController = new AbortController();
    const { signal, cleanup } = combineSignals(callerController.signal, null);

    expect(signal).toBe(callerController.signal);
    expect(cleanup).toBeUndefined();
  });

  it('returns init signal when caller is undefined', () => {
    const initController = new AbortController();
    const { signal, cleanup } = combineSignals(undefined, initController.signal);

    expect(signal).toBe(initController.signal);
    expect(cleanup).toBeUndefined();
  });
});
