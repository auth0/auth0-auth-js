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
    const mergedHeaders = headers ? new Headers(init?.headers) : undefined;
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
