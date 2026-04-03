import { test, expect } from 'vitest';
import { AuthClient } from '../dist/index.js';

test('AuthClient can be instantiated', () => {
  const client = new AuthClient({
    domain: 'example.auth0.com',
    clientId: 'client-id',
    clientSecret: 'client-secret',
  });

  expect(client).toBeDefined();
});
