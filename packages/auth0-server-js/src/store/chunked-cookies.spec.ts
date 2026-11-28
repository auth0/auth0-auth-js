import { expect, test } from 'vitest';
import { getChunkIndex } from './chunked-cookies.js';

test('getChunkIndex - returns the index of a cookie named <identifier>.<index>', () => {
  expect(getChunkIndex('<identifier>', '<identifier>.0')).toBe(0);
  expect(getChunkIndex('<identifier>', '<identifier>.12')).toBe(12);
});

test.each([
  '<identifier>',
  '<identifier>.',
  '<identifier>.x',
  '<identifier>.1.2',
  '<identifier>.01',
  '<identifier>.-1',
  '<identifier>_theme',
  '<identifier>x.0',
  'other.0',
])('getChunkIndex - returns undefined for %s', (name) => {
  expect(getChunkIndex('<identifier>', name)).toBeUndefined();
});

test('getChunkIndex - works for identifiers that contain dots or regular expression characters', () => {
  expect(getChunkIndex('my.sess', 'my.sess.3')).toBe(3);
  expect(getChunkIndex('my.sess', 'myXsess.3')).toBeUndefined();
  expect(getChunkIndex('my', 'my.sess.0')).toBeUndefined();
  expect(getChunkIndex('a+b', 'a+b.0')).toBe(0);
  expect(getChunkIndex('a+b', 'aab.0')).toBeUndefined();
});
