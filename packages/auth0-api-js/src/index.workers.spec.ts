import { test, expect } from 'vitest';
import { ApiClient } from '../dist/index.js';

test('ApiClient can be instantiated', () => {
  const client = new ApiClient({
    domain: 'example.auth0.com',
    audience: 'https://api.example.com/',
  });

  expect(client).toBeDefined();
});
