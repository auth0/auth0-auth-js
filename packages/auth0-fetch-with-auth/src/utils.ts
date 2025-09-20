import { CustomFetchMinimalOutput, ResponseHeaders } from "./types.js";

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

  export function hasUseDpopNonceError<TOutput extends CustomFetchMinimalOutput>(response: TOutput): boolean {
    if (response.status !== 401) {
      return false;
    }

    const wwwAuthHeader = getHeader(response.headers, 'www-authenticate');

    return wwwAuthHeader.includes('use_dpop_nonce');
  }