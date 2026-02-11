import { expect, test, describe, beforeEach, afterEach } from 'vitest';
import { AuthClient } from './auth-client.js';
import { MissingRequiredArgumentError } from './errors.js';

describe('AuthClient - Environment Variable Support', () => {
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
      process.env.AUTH0_CLIENT_ID = 'env-client-id';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';

      const authClient = new AuthClient({});

      // Verify the client was created successfully with env vars
      expect(authClient).toBeDefined();
      expect(authClient.mfa).toBeDefined();
    });

    test('should use mixed environment variables and explicit options', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      // No CLIENT_ID in env

      const authClient = new AuthClient({
        clientId: 'explicit-client-id',
        clientSecret: 'explicit-client-secret',
      });

      expect(authClient).toBeDefined();
    });
  });

  describe('Explicit options override environment variables', () => {
    test('should override AUTH0_DOMAIN with explicit domain option', () => {
      // Set env var to empty string which would normally fail
      process.env.AUTH0_DOMAIN = '';
      process.env.AUTH0_CLIENT_ID = 'client-id';
      process.env.AUTH0_CLIENT_SECRET = 'client-secret';

      // But providing explicit domain should work, proving override is working
      const authClient = new AuthClient({
        domain: 'correct-domain.auth0.com',
      });

      expect(authClient).toBeDefined();
    });

    test('should override AUTH0_CLIENT_ID with explicit clientId option', () => {
      // Set env var to empty string which would normally fail
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = '';
      process.env.AUTH0_CLIENT_SECRET = 'client-secret';

      // But providing explicit clientId should work, proving override is working
      const authClient = new AuthClient({
        clientId: 'correct-client-id',
      });

      expect(authClient).toBeDefined();
    });

    test('should override AUTH0_CLIENT_SECRET with explicit clientSecret option', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'client-id';
      // No CLIENT_SECRET in env, would normally require requireClientAuth: false

      // But providing explicit clientSecret should allow requireClientAuth: true
      const authClient = new AuthClient({
        clientSecret: 'explicit-secret',
      });

      expect(authClient).toBeDefined();
    });

    test('should treat undefined options as "use environment variable"', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'env-client-id';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';

      const authClient = new AuthClient({
        domain: undefined,
        clientId: undefined,
        clientSecret: undefined,
      });

      expect(authClient).toBeDefined();
    });
  });

  describe('Required field validation', () => {
    test('should throw MissingRequiredArgumentError when domain is missing from both options and environment', () => {
      process.env.AUTH0_CLIENT_ID = 'client-id';
      delete process.env.AUTH0_DOMAIN;

      try {
        new AuthClient({});
        expect.fail('Should have thrown MissingRequiredArgumentError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingRequiredArgumentError);
        expect((error as MissingRequiredArgumentError).code).toBe('missing_required_argument_error');
        expect((error as MissingRequiredArgumentError).message).toBe(
          'The argument \'domain\' is required but was not provided.'
        );
      }
    });

    test('should throw MissingRequiredArgumentError when clientId is missing from both options and environment', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      delete process.env.AUTH0_CLIENT_ID;

      try {
        new AuthClient({});
        expect.fail('Should have thrown MissingRequiredArgumentError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingRequiredArgumentError);
        expect((error as MissingRequiredArgumentError).code).toBe('missing_required_argument_error');
        expect((error as MissingRequiredArgumentError).message).toBe(
          'The argument \'clientId\' is required but was not provided.'
        );
      }
    });

    test('should treat empty string as missing value (not fall back to env)', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'env-client-id';

      try {
        new AuthClient({
          domain: '',
          clientId: '',
        });
        expect.fail('Should have thrown MissingRequiredArgumentError');
      } catch (error) {
        expect(error).toBeInstanceOf(MissingRequiredArgumentError);
        expect((error as MissingRequiredArgumentError).code).toBe('missing_required_argument_error');
        expect((error as MissingRequiredArgumentError).message).toContain('required');
      }
    });
  });

  describe('Client authentication', () => {
    test('should use AUTH0_CLIENT_SECRET from environment when available', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'client-id';
      process.env.AUTH0_CLIENT_SECRET = 'client-secret';

      const authClient = new AuthClient({});

      expect(authClient).toBeDefined();
    });

    test('should use AUTH0_CLIENT_ASSERTION_SIGNING_KEY from environment when available', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'client-id';
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY = '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----';

      const authClient = new AuthClient();

      expect(authClient).toBeDefined();
    });
  });
});
