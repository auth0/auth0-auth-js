import { describe, expect, test } from 'vitest';

import { isRecord } from './is-record.js';

describe('isRecord', () => {
  test.each([
    ['an empty object', {}],
    ['an object with members', { a: 1 }],
    ['an object with no prototype', Object.create(null)],
    ['an instance of a class', new (class Example {})()],
    ['a Map', new Map()],
  ])('accepts %s', (_name, value) => {
    expect(isRecord(value)).toBe(true);
  });

  test.each([
    ['null', null],
    ['undefined', undefined],
    ['an array', []],
    ['an array with members', [1, 2]],
    ['a string', 'text'],
    ['a number', 1],
    ['a boolean', true],
    ['a function', () => ({})],
  ])('refuses %s', (_name, value) => {
    expect(isRecord(value)).toBe(false);
  });
});
