import { describe, expect, test } from 'vitest';
import { ensureUrlWithBaseUrl } from './utils.js';

describe('Utils', () => {
  describe('ensureUrlWithBaseUrl', () => {
    describe('when url is a string', () => {
      test('should return same value when no baseUrl', () => {
        const value = 'https://example.com/test';
        expect(ensureUrlWithBaseUrl(value)).toBe(value);
      });

      test('should return same value when baseUrl, but URL is absolute', () => {
        const value = 'https://example.com/test';
        expect(ensureUrlWithBaseUrl(value, 'https://another-example.com')).toBe(
          value
        );
      });

      test('should return correct value when baseUrl, and URL is not absolute', () => {
        const value = '/test';
        expect(ensureUrlWithBaseUrl(value, 'https://another-example.com')).toBe(
          'https://another-example.com/test'
        );
      });
    });

    describe('when url is an URL instance', () => {
      test('should return same value when no baseUrl', () => {
        const value = new URL('https://example.com/test');
        expect(ensureUrlWithBaseUrl(value)).toBe(value);
      });

      test('should return same value when baseUrl, but URL is absolute', () => {
        const value = new URL('https://example.com/test');
        expect(ensureUrlWithBaseUrl(value, 'https://another-example.com')).toBe(
          value
        );
      });

      test('should return correct value when baseUrl, and URL is not absolute', () => {
        // We can not create a non-absolute URL instance directly, as that would throw.
        // So we create an object that behaves like one.
        const urlObject = {
          toString: () => '/test',
        };
        const url = Object.setPrototypeOf(urlObject, URL.prototype);

        expect(
          ensureUrlWithBaseUrl(
            url as URL,
            'https://another-example.com'
          ).toString()
        ).toBe('https://another-example.com/test');
      });
    });

    describe('when url is a RequestInfo instance', () => {
      test('should return same value when no baseUrl', () => {
        const value = new Request('https://example.com/test');
        expect(ensureUrlWithBaseUrl(value)).toBe(value);
      });

      test('should return same value when baseUrl, but URL is absolute', () => {
        const value = new Request('https://example.com/test');
        expect(ensureUrlWithBaseUrl(value, 'https://another-example.com')).toBe(
          value
        );
      });
    });
  });
});
