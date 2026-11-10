import { expect, test } from 'vitest';
import { createTestAgent } from '../dist/testing.js';

test.each(['ES256', 'PS384'] as const)('createTestAgent works with a %s agent', async (delegationAlg) => {
  const agent = await createTestAgent({ delegationAlg });

  const sessionJwt = await agent.createSessionJwt({
    aud: 'https://example.auth0.com/',
    htm: 'POST',
    htu: 'https://api.example.com/orders',
    accessToken: 'abc',
  });
  const response = await agent.fetch(agent.cimdUrl);

  expect(sessionJwt.split('.')).toHaveLength(3);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(agent.metadata);
});
