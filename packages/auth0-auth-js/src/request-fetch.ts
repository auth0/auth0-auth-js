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
    sources.forEach((s, i) => {
      const listener = listeners[i];
      if (listener) {
        s.removeEventListener('abort', listener);
      }
    });
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
 * Captured response metadata for a fetch call.
 * @internal
 */
interface CapturedResponse {
  status?: number;
  statusText?: string;
  headers?: Headers;
  bodyText?: Promise<string>;
}

/**
 * Fetch function that has been composed with response capture capability.
 * Allows callers to retrieve captured HTTP metadata (status, statusText, headers, bodyText)
 * from the most recent call without relying on `any` casts.
 * @internal
 */
export interface CapturingFetch {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  getCapturedResponse(): CapturedResponse;
}

/**
 * Builds a request-scoped `fetch` from {@link RequestOptions} for a single call.
 * Composes over a base fetch (already telemetry/mTLS-wrapped) so those behaviors
 * are preserved, and applies the caller's `signal`, merged `headers`, and/or a
 * one-off `customFetch`. Captures response metadata (status, statusText, headers, bodyText Promise)
 * and attaches it via getCapturedResponse property on the returned fetch.
 *
 * CRITICAL: Always builds per-call closure (drop early-return) to isolate captured state.
 * Ensures capture var is isolated per call with no concurrency leak.
 *
 * Reserved headers set by the SDK win: the telemetry `Auth0-Client` header is
 * applied last by the telemetry wrapper, and a caller-supplied `Authorization`
 * header is ignored.
 *
 * @param baseFetch The client's telemetry/mTLS-wrapped fetch.
 * @param requestOptions The caller's per-request options (may be undefined).
 * @param telemetryConfig Telemetry config used to re-wrap a per-request `customFetch`.
 * @returns A fetch function with getCapturedResponse property; invoke inline only (never store reference).
 */
export function composeRequestFetch(
  baseFetch: typeof fetch,
  requestOptions: RequestOptions | undefined,
  telemetryConfig: TelemetryConfig
): CapturingFetch {
  // CRITICAL: ALWAYS build per-call closure (drop early-return on no requestOptions).
  // Ensures capture var is isolated per call, no concurrency leak.
  const capturedResponse: CapturedResponse = {};

  const { signal, headers, customFetch: perRequestFetch } = requestOptions ?? {};

  // When a per-request fetch is supplied it replaces the base transport but is
  // re-wrapped with telemetry so the Auth0-Client header is still sent. (If mTLS
  // is in use, a per-request fetch must itself be mTLS-capable.)
  const base = perRequestFetch ? createTelemetryFetch(perRequestFetch, telemetryConfig) : baseFetch;

  // Build wrapper fetch that captures response metadata before oauth4webapi consumes it.
  const wrappedFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    // Apply per-request signal + headers merge if present.
    // If no requestOptions headers to merge and init already has headers, reuse them to minimize object creation.
    let finalHeaders: HeadersInit | undefined;

    if (headers) {
      // Need to merge requestOptions headers with init headers
      const mergedHeaders = new Headers(init?.headers);
      for (const [key, value] of Object.entries(headers)) {
        // Never let a caller override the SDK-set Authorization header.
        if (key.toLowerCase() === 'authorization') {
          continue;
        }
        mergedHeaders.set(key, value);
      }
      finalHeaders = mergedHeaders;
    } else if (init?.headers) {
      // No requestOptions headers to merge, just use init headers as-is
      finalHeaders = init.headers;
    }

    const response = await base(input, {
      ...init,
      ...(finalHeaders !== undefined && { headers: finalHeaders }),
      signal: combineSignals(signal, init?.signal),
    });

    // Capture BEFORE oauth4webapi consumes
    capturedResponse.status = response.status;
    capturedResponse.statusText = response.statusText;
    capturedResponse.headers = new Headers(response.headers);

    // Clone + start body read async (Promise stashed, not awaited here).
    // Error path: bodyText awaited in catch handler.
    // Success path: not used (headers/status only needed) — the promise is left
    // unawaited, so attach a swallow handler to avoid an unhandled rejection if
    // the cloned body stream errors on the success path.
    const cloned = response.clone();
    const bodyText = cloned.text() as Promise<string>;
    bodyText.catch(() => undefined);
    capturedResponse.bodyText = bodyText;

    return response; // Return original (bodyUsed=false); oauth4webapi consumes it.
  };

  // Attach getCapturedResponse as property on returned fetch function (non-standard but non-breaking).
  // @internal Callers must invoke getCapturedResponse() inline within try/catch block, never hold reference across calls.
  const capturingFetch = wrappedFetch as CapturingFetch;
  capturingFetch.getCapturedResponse = () => capturedResponse;

  return capturingFetch;
}
