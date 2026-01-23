import { describe, it, expect, vi } from 'vitest';
import { createTelemetryFetch } from './telemetry.js';

describe('telemetry', () => {
  describe('createTelemetryFetch', () => {
    it('should add Auth0-Client header to requests', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: '@auth0/test-package',
        version: '1.0.0',
      });

      await telemetryFetch('https://example.com/api');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init?.headers);

      expect(headers.get('Auth0-Client')).toBeDefined();
      const decoded = JSON.parse(
        Buffer.from(headers.get('Auth0-Client')!, 'base64').toString()
      );
      expect(decoded).toEqual({
        name: '@auth0/test-package',
        version: '1.0.0',
      });
    });

    it('should use custom name and version when provided', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: 'custom-app',
        version: '2.0.0',
      });

      await telemetryFetch('https://example.com/api');

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init?.headers);
      const decoded = JSON.parse(
        Buffer.from(headers.get('Auth0-Client')!, 'base64').toString()
      );

      expect(decoded).toEqual({
        name: 'custom-app',
        version: '2.0.0',
      });
    });

    it('should not add header when telemetry is disabled', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        enabled: false,
      });

      await telemetryFetch('https://example.com/api');

      expect(mockFetch).toBe(telemetryFetch);
    });

    it('should preserve existing headers', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: '@auth0/test-package',
        version: '1.0.0',
      });

      await telemetryFetch('https://example.com/api', {
        headers: {
          'Content-Type': 'application/json',
          'Custom-Header': 'value',
        },
      });

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init?.headers);

      expect(headers.get('Auth0-Client')).toBeDefined();
      expect(headers.get('Content-Type')).toBe('application/json');
      expect(headers.get('Custom-Header')).toBe('value');
    });

    it('should work with GET requests', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: '@auth0/test-package',
        version: '1.0.0',
      });

      await telemetryFetch('https://example.com/api', { method: 'GET' });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, init] = mockFetch.mock.calls[0];
      expect(init?.method).toBe('GET');
      const headers = new Headers(init?.headers);
      expect(headers.get('Auth0-Client')).toBeDefined();
    });

    it('should work with POST requests', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: '@auth0/test-package',
        version: '1.0.0',
      });

      await telemetryFetch('https://example.com/api', {
        method: 'POST',
        body: JSON.stringify({ data: 'test' }),
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, init] = mockFetch.mock.calls[0];
      expect(init?.method).toBe('POST');
      expect(init?.body).toBe(JSON.stringify({ data: 'test' }));
      const headers = new Headers(init?.headers);
      expect(headers.get('Auth0-Client')).toBeDefined();
    });

    it('should work with DELETE requests', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: '@auth0/test-package',
        version: '1.0.0',
      });

      await telemetryFetch('https://example.com/api', { method: 'DELETE' });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, init] = mockFetch.mock.calls[0];
      expect(init?.method).toBe('DELETE');
      const headers = new Headers(init?.headers);
      expect(headers.get('Auth0-Client')).toBeDefined();
    });

    it('should encode header value as base64', async () => {
      const mockFetch = vi.fn().mockResolvedValue(new Response());
      const telemetryFetch = createTelemetryFetch(mockFetch, {
        name: '@auth0/test-package',
        version: '1.0.0',
      });

      await telemetryFetch('https://example.com/api');

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init?.headers);
      const headerValue = headers.get('Auth0-Client')!;

      // Should be base64
      expect(headerValue).toMatch(/^[A-Za-z0-9+/=]+$/);

      // Should decode to valid JSON
      const decoded = Buffer.from(headerValue, 'base64').toString();
      expect(() => JSON.parse(decoded)).not.toThrow();
    });
  });
});
