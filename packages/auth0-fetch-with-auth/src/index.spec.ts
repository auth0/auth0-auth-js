import { expect, test } from 'vitest';

test('dummy test - true should be true', () => {
  expect(true).toBe(true);
});

test('dummy test - hello world function exists', () => {
  expect(typeof console.log).toBe('function');
});
