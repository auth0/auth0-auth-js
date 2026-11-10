// The entry point of `@auth0/auth0-api-js/testing`: helpers for the tests of code that uses this package. It is
// separate from the main entry point on purpose. Import it from tests only.
export { createTestAgent } from './poppy/testing/test-agent.js';
export type {
  CreateTestAgentOptions,
  TestAgent,
  TestSessionJwtDefect,
  TestSessionJwtOptions,
} from './poppy/testing/test-agent.js';
