import { expect, test } from 'vitest';
import { run } from './index.js';

test('run - should return hello world', async () => {
  expect(run()).toEqual('hello world');
});
