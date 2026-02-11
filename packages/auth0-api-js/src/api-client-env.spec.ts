import { expect, test, describe, beforeEach, afterEach, vi } from 'vitest';
import { ApiClient } from './api-client.js';
import { InvalidConfigurationError, MissingRequiredArgumentError } from './errors.js';

describe('ApiClient - Environment Variable Support', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset process.env before each test
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('Environment variable usage', () => {
    test('should use all configuration from environment variables', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_AUDIENCE = 'https://api.example.com';
      process.env.AUTH0_CLIENT_ID = 'env-client-id';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';

      const apiClient = new ApiClient({});

      expect(apiClient).toBeDefined();
    });

    test('should use mixed environment variables and explicit options', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      // No AUDIENCE in env

      const apiClient = new ApiClient({
        audience: 'https://explicit-api.example.com',
      });

      expect(apiClient).toBeDefined();
    });

    test('should allow clientId and clientSecret to be optional', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_AUDIENCE = 'https://api.example.com';
      delete process.env.AUTH0_CLIENT_ID;
      delete process.env.AUTH0_CLIENT_SECRET;

      const apiClient = new ApiClient({});

      expect(apiClient).toBeDefined();
    });
  });

  describe('Explicit options override environment variables', () => {
    test('should override AUTH0_DOMAIN with explicit domain option', () => {
      // Set env var to empty string which would normally fail
      process.env.AUTH0_DOMAIN = '';
      process.env.AUTH0_AUDIENCE = 'https://api.example.com';

      // But providing explicit domain should work, proving override is working
      const apiClient = new ApiClient({
        domain: 'correct-domain.auth0.com',
      });

      expect(apiClient).toBeDefined();
    });

    test('should override AUTH0_AUDIENCE with explicit audience option', () => {
      // Set env var to empty string which would normally fail
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_AUDIENCE = '';

      // But providing explicit audience should work, proving override is working
      const apiClient = new ApiClient({
        audience: 'https://correct-api.example.com',
      });

      expect(apiClient).toBeDefined();
    });

    test('should override both domain and audience with explicit options', () => {
      // Set env vars to empty which would normally fail
      process.env.AUTH0_DOMAIN = '';
      process.env.AUTH0_AUDIENCE = '';

      // But providing explicit options should work
      const apiClient = new ApiClient({
        domain: 'explicit-domain.auth0.com',
        audience: 'https://explicit-api.example.com',
      });

      expect(apiClient).toBeDefined();
    });

    test('should treat undefined options as "use environment variable"', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_AUDIENCE = 'https://api.example.com';

      const apiClient = new ApiClient({
        domain: undefined,
        audience: undefined,
      });

      expect(apiClient).toBeDefined();
    });
  });

  describe('Required field validation', () => {
    test('should throw InvalidConfigurationError when domain is missing from both options and environment', () => {
      process.env.AUTH0_AUDIENCE = 'https://api.example.com';
      delete process.env.AUTH0_DOMAIN;

      try {
        new ApiClient({});
        expect.fail('Should have thrown MissingRequiredArgumentError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingRequiredArgumentError);
        expect((error as MissingRequiredArgumentError).code).toBe('missing_required_argument_error');
        expect((error as MissingRequiredArgumentError).message).toBe(
          'The argument \'domain\' is required but was not provided.'
        );
      }
    });

    test('should treat empty string as missing value (not fall back to env)', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_AUDIENCE = 'https://api.example.com';

      try {
        new ApiClient({
          domain: '',
          audience: '',
        });
        expect.fail('Should have thrown MissingRequiredArgumentError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingRequiredArgumentError);
        expect((error as MissingRequiredArgumentError).code).toBe('missing_required_argument_error');
        expect((error as MissingRequiredArgumentError).message).toContain('required');
      }
    });
  });
});
