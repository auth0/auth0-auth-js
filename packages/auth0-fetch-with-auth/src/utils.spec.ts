import { describe, expect, test } from 'vitest';
import { extractUrl } from './utils.js';

describe('Utils', () => {
  describe('extractUrl', () => {
    test('should return the URL when a string is provided', () => {
      expect(extractUrl('https://example.com/path')).toBe(
        'https://example.com/path'
      );
    });
  });
});
