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
 */
export function combineSignals(
  callerSignal?: AbortSignal,
  initSignal?: AbortSignal | null
): AbortSignal | undefined {
  if (!callerSignal) {
    return initSignal ?? undefined;
  }
  if (!initSignal) {
    return callerSignal;
  }

  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
    return AbortSignal.any([callerSignal, initSignal]);
  }

  // Manual fallback for runtimes without AbortSignal.any.
  const controller = new AbortController();
  const sources = [callerSignal, initSignal];

  // If either source is already aborted, propagate immediately — no listeners.
  const alreadyAborted = sources.find((s) => s.aborted);
  if (alreadyAborted) {
    controller.abort((alreadyAborted as AbortSignal & { reason?: unknown }).reason);
    return controller.signal;
  }

  // Otherwise listen on both, and on the first abort detach *both* listeners so
  // a long-lived caller signal doesn't accumulate listeners across requests.
  const listeners: Array<() => void> = [];
  const cleanup = () => {
    sources.forEach((s, i) => s.removeEventListener('abort', listeners[i]));
  };
  sources.forEach((source, i) => {
    listeners[i] = () => {
      cleanup();
      controller.abort((source as AbortSignal & { reason?: unknown }).reason);
    };
    source.addEventListener('abort', listeners[i], { once: true });
  });
  return controller.signal;
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
    const mergedHeaders = new Headers(init?.headers);
    if (headers) {
      for (const [key, value] of Object.entries(headers)) {
        // Never let a caller override the SDK-set Authorization header.
        if (key.toLowerCase() === 'authorization') {
          continue;
        }
        mergedHeaders.set(key, value);
      }
    }
    return base(input, {
      ...init,
      headers: mergedHeaders,
      signal: combineSignals(signal, init?.signal),
    });
  };
}
