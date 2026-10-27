import { createTelemetryFetch, type TelemetryConfig } from './telemetry.js';
import type { RequestOptions } from './types.js';

/**
 * Combines a caller-supplied {@link AbortSignal} with a signal the SDK's
 * transport may already set on the request `init`, so the request aborts if
 * *either* fires. openid-client v6 installs its own timeout signal; a caller
 * `signal` must add to it, not erase it.
 *
 * Prefers the native `AbortSignal.any` (Node 20.3+ / modern browsers) and falls
 * back to a manual combinator on older runtimes.
 *
 * @returns The combined signal and an optional cleanup function. The cleanup
 *   function is present only when the manual fallback is used, and MUST be called
 *   on request completion (success or failure) to detach listeners from the source
 *   signals. Callers using the native `AbortSignal.any` path receive no cleanup fn.
 */
export function combineSignals(
  callerSignal?: AbortSignal,
  initSignal?: AbortSignal | null
): { signal: AbortSignal | undefined; cleanup?: () => void } {
  if (!callerSignal) {
    return { signal: initSignal ?? undefined };
  }
  if (!initSignal) {
    return { signal: callerSignal };
  }

  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
    return { signal: AbortSignal.any([callerSignal, initSignal]) };
  }

  // Manual fallback for runtimes without AbortSignal.any.
  const controller = new AbortController();
  const sources = [callerSignal, initSignal];

  // If either source is already aborted, propagate immediately — no listeners.
  const alreadyAborted = sources.find((s) => s.aborted);
  if (alreadyAborted) {
    controller.abort((alreadyAborted as AbortSignal & { reason?: unknown }).reason);
    return { signal: controller.signal };
  }

  // Otherwise listen on both, and on the first abort detach *both* listeners so
  // a long-lived caller signal doesn't accumulate listeners across requests.
  const listeners: Array<(() => void) | undefined> = [];
  const cleanup = () => {
    sources.forEach((s, i) => {
      const listener = listeners[i];
      if (listener) s.removeEventListener('abort', listener);
    });
  };
  sources.forEach((source, i) => {
    const listener = () => {
      cleanup();
      controller.abort((source as AbortSignal & { reason?: unknown }).reason);
    };
    listeners[i] = listener;
    source.addEventListener('abort', listener, { once: true });
  });
  return { signal: controller.signal, cleanup };
}

/**
 * The largest timer runtimes honour: above this they set a 1 ms timer instead of the one asked for, or throw.
 * A larger `httpTimeout` is capped to it. That is about 24.8 days, so it still means "no practical limit".
 *
 * @internal Not exported from package index.
 */
export const MAX_TIMER_MS = 2 ** 31 - 1;

/**
 * The message for an invalid `httpTimeout`.
 *
 * @internal Not exported from package index.
 */
export const HTTP_TIMEOUT_MESSAGE = 'httpTimeout must be a positive integer (milliseconds)';

/**
 * Whether `value` is a usable `httpTimeout`: a positive integer number of milliseconds.
 * `AbortSignal.timeout` throws on a fraction. `0` is rejected too: openid-client treats a falsy timeout as
 * "no timeout", while `AbortSignal.timeout(0)` aborts at once. Does not throw, so each consumer can raise its
 * own error type.
 *
 * @category Utilities
 */
export function isValidHttpTimeout(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

/**
 * Wraps a `fetch` so every request is also aborted after `timeoutMs`. If the request already carries a
 * signal (for example one installed by openid-client or jose, or passed by the caller), the request aborts
 * when either fires. Works on runtimes without `AbortSignal.any`.
 *
 * Each request gets its own limit; the time is not shared across a retry.
 *
 * @param baseFetch The fetch to wrap.
 * @param timeoutMs Time limit per request, in milliseconds. A positive integer.
 * @throws {TypeError} If `timeoutMs` is not valid (see {@link isValidHttpTimeout}).
 * @example
 * const fetchWithLimit = createTimeoutFetch(fetch, 10_000);
 */
export function createTimeoutFetch(baseFetch: typeof fetch, timeoutMs: number): typeof fetch {
  if (!isValidHttpTimeout(timeoutMs)) {
    throw new TypeError(HTTP_TIMEOUT_MESSAGE);
  }
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const combined = combineSignals(AbortSignal.timeout(Math.min(timeoutMs, MAX_TIMER_MS)), init?.signal);
    try {
      return await baseFetch(input, { ...init, signal: combined.signal });
    } finally {
      combined.cleanup?.();
    }
  };
}

/**
 * Fetch function composed with response-capture capability.
 * Allows the most recent HTTP {@link Response} to be retrieved after the call
 * for inclusion in an {@link ApiResponse} envelope.
 *
 * The captured reference is a clone of the live `Response` so the caller
 * receives a fresh body stream while openid-client consumes the original.
 *
 * @internal Not exported from package index.
 */
export interface CapturingFetch {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  getCapturedResponse(): Response | undefined;
}

/**
 * Wraps a base `fetch` so the most recent {@link Response} is retrievable via
 * `getCapturedResponse()` after the awaited call returns.
 *
 * Intended for per-call activation only. Create one wrapper per token call
 * when `fullResponse: true` is set; discard after use.
 *
 * @param baseFetch The telemetry/mTLS-wrapped fetch already composed for
 *   the current request.
 * @returns A branded fetch function with `getCapturedResponse` attached.
 * @internal
 */
// Per-invocation only — NEVER hoist to class field (concurrent calls would share capturedResponse).
export function createCapturingFetch(baseFetch: typeof fetch): CapturingFetch {
  let capturedResponse: Response | undefined;

  const wrappedFetch = async (
    input: RequestInfo | URL,
    init?: RequestInit
  ): Promise<Response> => {
    const response = await baseFetch(input, init);
    // clone() gives caller a fresh body; openid-client consumes the original.
    capturedResponse = response.clone();
    return response;
  };

  const capturingFetch = wrappedFetch as CapturingFetch;
  capturingFetch.getCapturedResponse = () => capturedResponse;
  return capturingFetch;
}

/**
 * Builds a request-scoped `fetch` from {@link RequestOptions} for a single call.
 * Composes over a base fetch (already telemetry/mTLS-wrapped) so those behaviors
 * are preserved, and applies the caller's `signal`, merged `headers`, and/or a
 * one-off `customFetch`. Returns the supplied `baseFetch` untouched when no
 * request options are provided.
 *
 * Reserved headers set by the SDK win: the telemetry `Auth0-Client` header is
 * applied last by the telemetry wrapper, and a caller-supplied `Authorization`
 * header is ignored.
 *
 * @param baseFetch The client's telemetry/mTLS-wrapped fetch.
 * @param requestOptions The caller's per-request options (may be undefined).
 * @param telemetryConfig Telemetry config used to re-wrap a per-request `customFetch`.
 */
export function composeRequestFetch(
  baseFetch: typeof fetch,
  requestOptions: RequestOptions | undefined,
  telemetryConfig: TelemetryConfig
): typeof fetch {
  if (!requestOptions) {
    return baseFetch;
  }

  const { signal, headers, customFetch: perRequestFetch } = requestOptions;

  // When a per-request fetch is supplied it replaces the base transport but is
  // re-wrapped with telemetry so the Auth0-Client header is still sent. (If mTLS
  // is in use, a per-request fetch must itself be mTLS-capable.)
  const base = perRequestFetch ? createTelemetryFetch(perRequestFetch, telemetryConfig) : baseFetch;

  if (!signal && !headers) {
    return base;
  }

  return async (input: RequestInfo | URL, init?: RequestInit) => {
    // openid-client always passes a string URL as `input`; the Request branch
    // is included for forward-compatibility if callers invoke composeRequestFetch directly.
    const mergedHeaders = headers
      ? new Headers(input instanceof Request ? input.headers : undefined)
      : undefined;
    if (mergedHeaders && init?.headers) {
      new Headers(init.headers).forEach((value, key) => mergedHeaders.set(key, value));
    }
    if (headers) {
      for (const [key, value] of Object.entries(headers)) {
        const lowerKey = key.toLowerCase();
        // Never let a caller override SDK-reserved headers.
        if (lowerKey === 'authorization' || lowerKey === 'auth0-client') {
          continue;
        }
        mergedHeaders!.set(key, value);
      }
    }
    const combined = combineSignals(signal, init?.signal);
    try {
      return await base(input, {
        ...init,
        ...(mergedHeaders && { headers: mergedHeaders }),
        signal: combined.signal,
      });
    } finally {
      combined.cleanup?.();
    }
  };
}
