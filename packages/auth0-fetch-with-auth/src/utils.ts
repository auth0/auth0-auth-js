import { CustomFetchMinimalOutput, ResponseHeaders } from './types.js';

export function isAbsoluteUrl(url: string): boolean {
  // `http://example.com`, `https://example.com` or `//example.com`
  return /^(https?:)?\/\//i.test(url);
}

export function buildUrl(
  baseUrl: string | undefined,
  url: string | undefined
): string {
  if (url) {
    if (isAbsoluteUrl(url)) {
      return url;
    }

    if (baseUrl) {
      return `${baseUrl.replace(/\/?\/$/, '')}/${url.replace(/^\/+/, '')}`;
    }
  }

  throw new TypeError('`url` must be absolute or `baseUrl` non-empty.');
}

export function getHeader(headers: ResponseHeaders, name: string): string {
  if (Array.isArray(headers)) {
    return new Headers(headers).get(name) || '';
  }

  if (typeof headers.get === 'function') {
    return headers.get(name) || '';
  }

  return (headers as Record<string, string | null | undefined>)[name] || '';
}

export function hasUseDpopNonceError<TOutput extends CustomFetchMinimalOutput>(
  response: TOutput
): boolean {
  if (response.status !== 401) {
    return false;
  }

  const wwwAuthHeader = getHeader(response.headers, 'www-authenticate');

  return wwwAuthHeader.includes('use_dpop_nonce');
}

/**
 * Retries a function on error based on the provided options.
 * @param fn Function that performs the operation to be retried
 * @param options Options for retry behavior
 * @returns The result of the function if successful
 * @throws The last error encountered if all retries fail
 */
export function retryOnError<TOutput>(
  fn: () => Promise<TOutput>,
  options: { shouldRetry: (e: unknown) => boolean; maxRetries?: number }
): Promise<TOutput> {
  const defaultMaxRetries = 1;
  const maxRetries = options.maxRetries ?? defaultMaxRetries;
  let attempt = 0;
  let lastError: unknown | undefined;

  async function execute(): Promise<TOutput> {
    try {
      return fn();
    } catch (e) {
      // Only retry if the error matches the criteria and we haven't exceeded max retries.
      if (options.shouldRetry(e) && attempt < maxRetries) {
        attempt++;
        lastError = e;
        return execute();
      }

      // Attach the original error as a cause for better stack trace context
      if (e instanceof Error && lastError && e !== lastError) {
        e.cause = lastError;
      }
      throw e;
    }
  }

  return execute();
}
