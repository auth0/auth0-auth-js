import { describe, expect, test } from 'vitest';
import {
  extractUrl,
  isAbsoluteUrl,
  buildUrl,
  getHeader,
  hasUseDpopNonceError,
  retryOnError,
} from './utils.js';

describe('Utils', () => {
  describe('isAbsoluteUrl', () => {
    test('should return true for http URLs', () => {
      expect(isAbsoluteUrl('http://example.com')).toBe(true);
      expect(isAbsoluteUrl('http://example.com/path')).toBe(true);
    });

    test('should return true for https URLs', () => {
      expect(isAbsoluteUrl('https://example.com')).toBe(true);
      expect(isAbsoluteUrl('https://example.com/path')).toBe(true);
    });

    test('should return true for protocol-relative URLs', () => {
      expect(isAbsoluteUrl('//example.com')).toBe(true);
      expect(isAbsoluteUrl('//example.com/path')).toBe(true);
    });

    test('should return false for relative URLs', () => {
      expect(isAbsoluteUrl('/path')).toBe(false);
      expect(isAbsoluteUrl('path')).toBe(false);
      expect(isAbsoluteUrl('./path')).toBe(false);
      expect(isAbsoluteUrl('../path')).toBe(false);
    });

    test('should be case insensitive', () => {
      expect(isAbsoluteUrl('HTTP://example.com')).toBe(true);
      expect(isAbsoluteUrl('HTTPS://example.com')).toBe(true);
    });
  });

  describe('extractUrl', () => {
    test('should return the URL when a string is provided', () => {
      expect(extractUrl('https://example.com/path')).toBe(
        'https://example.com/path'
      );
    });

    test('should return href when a URL object is provided', () => {
      const url = new URL('https://example.com/path');
      expect(extractUrl(url)).toBe('https://example.com/path');
    });

    test('should return url property when a Request object is provided', () => {
      const request = new Request('https://example.com/path');
      expect(extractUrl(request)).toBe('https://example.com/path');
    });
  });

  describe('buildUrl', () => {
    test('should return absolute URL as-is', () => {
      expect(buildUrl(undefined, 'https://example.com/path')).toBe(
        'https://example.com/path'
      );
      expect(buildUrl('https://base.com', 'https://example.com/path')).toBe(
        'https://example.com/path'
      );
    });

    test('should combine baseUrl and relative path', () => {
      expect(buildUrl('https://example.com', 'path')).toBe(
        'https://example.com/path'
      );
      expect(buildUrl('https://example.com', '/path')).toBe(
        'https://example.com/path'
      );
    });

    test('should handle baseUrl with trailing slash', () => {
      expect(buildUrl('https://example.com/', 'path')).toBe(
        'https://example.com/path'
      );
      expect(buildUrl('https://example.com/', '/path')).toBe(
        'https://example.com/path'
      );
    });

    test('should handle baseUrl with double trailing slashes', () => {
      // The regex /\/?\/$/ only removes the last slash and one optional preceding slash
      expect(buildUrl('https://example.com//', 'path')).toBe(
        'https://example.com/path'
      );
    });

    test('should treat path with multiple leading slashes as protocol-relative URL', () => {
      // ///path matches the absolute URL pattern (protocol-relative)
      expect(buildUrl('https://example.com', '///path')).toBe('///path');
    });

    test('should throw error when url is undefined and baseUrl is undefined', () => {
      expect(() => buildUrl(undefined, undefined)).toThrow(
        '`url` must be absolute or `baseUrl` non-empty.'
      );
    });

    test('should throw error when url is relative and baseUrl is undefined', () => {
      expect(() => buildUrl(undefined, 'path')).toThrow(
        '`url` must be absolute or `baseUrl` non-empty.'
      );
    });

    test('should throw error when url is relative and baseUrl is empty', () => {
      expect(() => buildUrl('', 'path')).toThrow(
        '`url` must be absolute or `baseUrl` non-empty.'
      );
    });

    test('should handle protocol-relative URLs', () => {
      expect(buildUrl('https://base.com', '//example.com/path')).toBe(
        '//example.com/path'
      );
    });
  });

  describe('getHeader', () => {
    test('should get header from Headers object', () => {
      const headers = new Headers({ 'content-type': 'application/json' });
      expect(getHeader(headers, 'content-type')).toBe('application/json');
    });

    test('should return empty string for non-existent header in Headers object', () => {
      const headers = new Headers();
      expect(getHeader(headers, 'x-custom')).toBe('');
    });

    test('should get header from array of tuples', () => {
      const headers: [string, string][] = [
        ['content-type', 'application/json'],
      ];
      expect(getHeader(headers, 'content-type')).toBe('application/json');
    });

    test('should return empty string for non-existent header in array', () => {
      const headers: [string, string][] = [
        ['content-type', 'application/json'],
      ];
      expect(getHeader(headers, 'x-custom')).toBe('');
    });

    test('should get header from plain object', () => {
      const headers = { 'content-type': 'application/json' };
      expect(getHeader(headers, 'content-type')).toBe('application/json');
    });

    test('should return empty string for non-existent header in plain object', () => {
      const headers = { 'content-type': 'application/json' };
      expect(getHeader(headers, 'x-custom')).toBe('');
    });

    test('should handle null values in plain object', () => {
      const headers = { 'content-type': null };
      expect(getHeader(headers, 'content-type')).toBe('');
    });

    test('should handle undefined values in plain object', () => {
      const headers = { 'content-type': undefined };
      expect(getHeader(headers, 'content-type')).toBe('');
    });

    test('should be case insensitive with Headers object', () => {
      const headers = new Headers({ 'Content-Type': 'application/json' });
      expect(getHeader(headers, 'content-type')).toBe('application/json');
    });
  });

  describe('hasUseDpopNonceError', () => {
    test('should return true when status is 401 and www-authenticate contains use_dpop_nonce', () => {
      const response = new Response(null, {
        status: 401,
        headers: {
          'www-authenticate': 'DPoP error="use_dpop_nonce"',
        },
      });
      expect(hasUseDpopNonceError(response)).toBe(true);
    });

    test('should return false when status is not 401', () => {
      const response = new Response(null, {
        status: 400,
        headers: {
          'www-authenticate': 'DPoP error="use_dpop_nonce"',
        },
      });
      expect(hasUseDpopNonceError(response)).toBe(false);
    });

    test('should return false when www-authenticate does not contain use_dpop_nonce', () => {
      const response = new Response(null, {
        status: 401,
        headers: {
          'www-authenticate': 'Bearer error="invalid_token"',
        },
      });
      expect(hasUseDpopNonceError(response)).toBe(false);
    });

    test('should return false when www-authenticate header is missing', () => {
      const response = new Response(null, {
        status: 401,
      });
      expect(hasUseDpopNonceError(response)).toBe(false);
    });

    test('should return false for 200 status', () => {
      const response = new Response(null, {
        status: 200,
        headers: {
          'www-authenticate': 'DPoP error="use_dpop_nonce"',
        },
      });
      expect(hasUseDpopNonceError(response)).toBe(false);
    });
  });

  describe('retryOnError', () => {
    test('should return result on first successful attempt', async () => {
      const fn = async () => 'success';
      const result = await retryOnError(fn, {
        shouldRetry: () => true,
      });
      expect(result).toBe('success');
    });

    test('should retry once on error when shouldRetry returns true', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts === 1) {
          throw new Error('First attempt failed');
        }
        return 'success';
      };
      const result = await retryOnError(fn, {
        shouldRetry: () => true,
      });
      expect(result).toBe('success');
      expect(attempts).toBe(2);
    });

    test('should not retry when shouldRetry returns false', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        throw new Error('Failed');
      };
      await expect(
        retryOnError(fn, {
          shouldRetry: () => false,
        })
      ).rejects.toThrow('Failed');
      expect(attempts).toBe(1);
    });

    test('should retry up to maxRetries times', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts <= 3) {
          throw new Error(`Attempt ${attempts} failed`);
        }
        return 'success';
      };
      const result = await retryOnError(fn, {
        shouldRetry: () => true,
        maxRetries: 3,
      });
      expect(result).toBe('success');
      expect(attempts).toBe(4);
    });

    test('should throw error when maxRetries is exceeded', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        throw new Error('Always fails');
      };
      await expect(
        retryOnError(fn, {
          shouldRetry: () => true,
          maxRetries: 2,
        })
      ).rejects.toThrow('Always fails');
      expect(attempts).toBe(3); // 1 initial + 2 retries
    });

    test('should use default maxRetries of 1 when not specified', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        throw new Error('Always fails');
      };
      await expect(
        retryOnError(fn, {
          shouldRetry: () => true,
        })
      ).rejects.toThrow('Always fails');
      expect(attempts).toBe(2); // 1 initial + 1 retry
    });

    test('should pass error to shouldRetry callback', async () => {
      const errors: Error[] = [];
      const fn = async () => {
        throw new Error('Test error');
      };
      await expect(
        retryOnError(fn, {
          shouldRetry: (e) => {
            errors.push(e as Error);
            return false;
          },
        })
      ).rejects.toThrow('Test error');
      expect(errors).toHaveLength(1);
      expect(errors[0].message).toBe('Test error');
    });

    test('should conditionally retry based on error', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts === 1) {
          throw new Error('Retryable error');
        }
        if (attempts === 2) {
          throw new Error('Non-retryable error');
        }
        return 'success';
      };
      await expect(
        retryOnError(fn, {
          shouldRetry: (e) => {
            const error = e as Error;
            return error.message === 'Retryable error';
          },
        })
      ).rejects.toThrow('Non-retryable error');
      expect(attempts).toBe(2);
    });

    test('should attach lastError as cause when different from current error', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts === 1) {
          throw new Error('First error');
        }
        throw new Error('Second error');
      };
      try {
        await retryOnError(fn, {
          shouldRetry: () => true,
        });
      } catch (e) {
        const error = e as Error;
        expect(error.message).toBe('Second error');
        expect((error.cause as Error).message).toBe('First error');
      }
    });

    test('should handle non-Error objects being thrown', async () => {
      const fn = async () => {
        throw 'string error';
      };
      await expect(
        retryOnError(fn, {
          shouldRetry: () => false,
        })
      ).rejects.toBe('string error');
    });
  });
});
