import { describe, expect, test } from 'vitest';

import { isCompatibleVersion, isServedVersion } from './version.js';

describe('isCompatibleVersion', () => {
  test.each([
    ['1.0', '1.0'],
    ['1.1', '1.0'],
    ['1.0', '1.1'],
    ['1.9', '1.2'],
    ['2.0', '2.3'],
    ['0.4', '0.4'],
  ])('%s is compatible with %s', (requested, served) => {
    expect(isCompatibleVersion(requested, served)).toBe(true);
  });

  test.each([
    ['2.0', '1.0'],
    ['1.0', '2.0'],
    ['0.4', '0.3'],
    ['0.3', '0.4'],
    ['0.4', '1.0'],
    ['1.0', '0.4'],
  ])('%s is not compatible with %s', (requested, served) => {
    expect(isCompatibleVersion(requested, served)).toBe(false);
  });

  test.each([
    '',
    '1',
    '1.',
    '.1',
    '1.0.0',
    'v1.0',
    '1.x',
    ' 1.0',
    '1.0 ',
    '-1.0',
    '1.-0',
    '12345.0',
    '1.12345',
    // A number with a leading zero is not a version of the SDK (the specification does not say so, the SDK keeps one spelling), and neither is a minor of `00`.
    '01.0',
    '1.00',
    '1.01',
    '00.1',
    '001.0',
  ])('is never compatible when the request says %j', (requested) => {
    expect(isCompatibleVersion(requested, '1.0')).toBe(false);
  });

  test('is not compatible with a served version that is not a version', () => {
    expect(isCompatibleVersion('1.0', 'one')).toBe(false);
  });
});

describe('isCompatibleVersion | numbers with zero', () => {
  test('a version of 0 as the major or the minor is a version', () => {
    expect(isCompatibleVersion('0.0', '0.0')).toBe(true);
    expect(isCompatibleVersion('1.0', '1.10')).toBe(true);
    expect(isCompatibleVersion('10.0', '10.5')).toBe(true);
    expect(isCompatibleVersion('1.0', '10.0')).toBe(false);
  });
});

describe('isServedVersion', () => {
  test('is true when one of the served versions is compatible', () => {
    expect(isServedVersion('2.0', ['1.0', '2.0'])).toBe(true);
    expect(isServedVersion('1.2', ['1.0', '2.0'])).toBe(true);
  });

  test('is false when none is compatible, and for an empty list', () => {
    expect(isServedVersion('3.0', ['1.0', '2.0'])).toBe(false);
    expect(isServedVersion('1.0', [])).toBe(false);
  });
});
