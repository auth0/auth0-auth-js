import { expect, test, describe, beforeEach, afterEach } from 'vitest';
import { ServerClient } from './server-client.js';
import { DefaultStateStore } from './test-utils/default-state-store.js';
import { DefaultTransactionStore } from './test-utils/default-transaction-store.js';
import { MissingClientAuthError } from '@auth0/auth0-auth-js';

describe('ServerClient - Environment Variable Support', () => {
  const originalEnv = process.env;
  const stateStore = new DefaultStateStore({ secret: '<secret>' });
  const transactionStore = new DefaultTransactionStore({ secret: '<secret>' });

  beforeEach(() => {
    // Reset process.env before each test
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('Environment variable usage', () => {
    test('should allow using configuration from environment variables', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'env-client-id';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';

      const serverClient = new ServerClient({
        stateStore,
        transactionStore,
      });

      expect(serverClient).toBeDefined();
    });

    test('should allow using mixed environment variables and explicit options', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';

      const serverClient = new ServerClient({
        clientId: 'explicit-client-id',
        stateStore,
        transactionStore,
      });

      expect(serverClient).toBeDefined();
    });
  });

  describe('Explicit options override environment variables', () => {
    test('should override AUTH0_DOMAIN with explicit domain option', () => {
      process.env.AUTH0_CLIENT_ID = 'client-id';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';
      // Set env var to empty string which would normally fail
      process.env.AUTH0_DOMAIN = '';

      // But providing explicit domain should work, proving override is working
      const serverClient = new ServerClient({
        domain: 'correct-domain.auth0.com',
        stateStore,
        transactionStore,
      });

      expect(serverClient).toBeDefined();
    });

    test('should override AUTH0_CLIENT_ID with explicit clientId option', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';
      // Set env var to empty string which would normally fail
      process.env.AUTH0_CLIENT_ID = '';

      // But providing explicit clientId should work, proving override is working
      const serverClient = new ServerClient({
        clientId: 'correct-client-id',
        stateStore,
        transactionStore,
      });

      expect(serverClient).toBeDefined();
    });

    test('should override AUTH0_CLIENT_SECRET with explicit clientSecret option', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'client-id';
      // Set env var to empty string which would normally fail
      process.env.AUTH0_CLIENT_SECRET = '';

      // But providing explicit clientSecret should work, proving override is working
      const serverClient = new ServerClient({
        clientSecret: 'explicit-secret',
        stateStore,
        transactionStore,
      });

      expect(serverClient).toBeDefined();
    });

    test('should treat undefined options as "use environment variable"', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'env-client-id';
      process.env.AUTH0_CLIENT_SECRET = 'env-client-secret';

      const serverClient = new ServerClient({
        domain: undefined,
        clientId: undefined,
        clientSecret: undefined,
        stateStore,
        transactionStore,
      });

      expect(serverClient).toBeDefined();
    });
  });

  describe('Required field validation', () => {
    test('should throw error when domain is missing from both options and environment', () => {
      process.env.AUTH0_CLIENT_ID = 'client-id';
      delete process.env.AUTH0_DOMAIN;

      try {
        new ServerClient({
          stateStore,
          transactionStore,
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe("The argument 'domain' is required but was not provided.");
      }
    });

    test('should throw error when clientId is missing from both options and environment', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      delete process.env.AUTH0_CLIENT_ID;

      try {
        new ServerClient({
          stateStore,
          transactionStore,
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe("The argument 'clientId' is required but was not provided.");
      }
    });

    test('should throw error when clientSecret and clientAssertionSigningKey are missing from both options and environment', () => {
      process.env.AUTH0_DOMAIN = 'domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'client-id';
      delete process.env.AUTH0_CLIENT_SECRET;
      delete process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY;

      try {
        new ServerClient({
          stateStore,
          transactionStore,
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error).toBeInstanceOf(MissingClientAuthError);
        expect((error as Error).message).toBe('The client secret or client assertion signing key must be provided.');
      }
    });

    test('should treat empty string as missing value (not fall back to env)', () => {
      process.env.AUTH0_DOMAIN = 'env-domain.auth0.com';
      process.env.AUTH0_CLIENT_ID = 'env-client-id';

      try {
        new ServerClient({
          domain: '',
          clientId: '',
          stateStore,
          transactionStore,
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toContain('required');
      }
    });
  });
});
