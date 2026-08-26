import { describe, it, expect } from 'vitest';
import { filterSensitiveHeaders, attachHttpMetadata } from './utils.js';

describe('filterSensitiveHeaders', () => {
  it('strips Set-Cookie', () => {
    const source = new Headers({ 'set-cookie': 'session=abc; HttpOnly', 'x-req-id': '123' });
    const filtered = filterSensitiveHeaders(source);
    expect(filtered.get('set-cookie')).toBeNull();
    expect(filtered.get('x-req-id')).toBe('123');
  });

  it('preserves Retry-After', () => {
    const source = new Headers({ 'retry-after': '60', 'set-cookie': 'sid=x' });
    const filtered = filterSensitiveHeaders(source);
    expect(filtered.get('retry-after')).toBe('60');
    expect(filtered.get('set-cookie')).toBeNull();
  });

  it('preserves x-ratelimit-remaining', () => {
    const source = new Headers({ 'x-ratelimit-remaining': '42' });
    const filtered = filterSensitiveHeaders(source);
    expect(filtered.get('x-ratelimit-remaining')).toBe('42');
  });

  it('strips Set-Cookie case-insensitively (SET-COOKIE)', () => {
    // Headers normalizes names, so SET-COOKIE and set-cookie are the same bucket
    const source = new Headers();
    source.append('set-cookie', 'a=1');
    source.append('set-cookie', 'b=2');
    const filtered = filterSensitiveHeaders(source);
    expect(filtered.get('set-cookie')).toBeNull();
  });

  it('returns empty Headers on hostile input (non-iterable headers bag)', () => {
    // Pass something that looks like Headers but throws on iteration
    const hostile = {
      [Symbol.iterator]() {
        throw new Error('hostile');
      },
      entries() {
        throw new Error('hostile');
      },
      forEach() {
        throw new Error('hostile');
      },
    };
    // Node's Headers constructor accepts a HeadersInit; passing an invalid value should
    // trigger the catch path and return empty Headers.
    const result = filterSensitiveHeaders(hostile as unknown as Headers);
    expect(result).toBeInstanceOf(Headers);
  });
});

describe('attachHttpMetadata', () => {
  it('reads statusCode and headers from error .response', () => {
    const responseHeaders = new Headers({ 'retry-after': '30', 'set-cookie': 'sid=x' });
    const e = { response: { status: 429, headers: responseHeaders } };
    const err: { statusCode?: number; headers?: Headers } = {};
    attachHttpMetadata(err, e);
    expect(err.statusCode).toBe(429);
    expect(err.headers?.get('retry-after')).toBe('30');
    expect(err.headers?.get('set-cookie')).toBeNull();
  });

  it('falls back to captured response when error has no .response', () => {
    const responseHeaders = new Headers({ 'x-req-id': 'fallback' });
    const captured = { status: 400, headers: responseHeaders } as unknown as Response;
    const e = new Error('network error');
    const err: { statusCode?: number; headers?: Headers } = {};
    attachHttpMetadata(err, e, captured);
    expect(err.statusCode).toBe(400);
    expect(err.headers?.get('x-req-id')).toBe('fallback');
  });

  it('leaves statusCode and headers undefined for network errors with no captured response', () => {
    const e = new TypeError('fetch failed');
    const err: { statusCode?: number; headers?: Headers } = {};
    attachHttpMetadata(err, e);
    expect(err.statusCode).toBeUndefined();
    expect(err.headers).toBeUndefined();
  });

  it('uses .status from error when present', () => {
    const e = { status: 401, response: { status: 401, headers: new Headers() } };
    const err: { statusCode?: number; headers?: Headers } = {};
    attachHttpMetadata(err, e);
    expect(err.statusCode).toBe(401);
  });

  it('strips Set-Cookie from headers attached via error .response', () => {
    const responseHeaders = new Headers({ 'set-cookie': 'token=secret', 'x-req-id': 'abc' });
    const e = { response: { status: 400, headers: responseHeaders } };
    const err: { statusCode?: number; headers?: Headers } = {};
    attachHttpMetadata(err, e);
    expect(err.headers?.get('set-cookie')).toBeNull();
    expect(err.headers?.get('x-req-id')).toBe('abc');
  });

  it('handles primitive thrown value gracefully', () => {
    const err: { statusCode?: number; headers?: Headers } = {};
    attachHttpMetadata(err, 'string error');
    expect(err.statusCode).toBeUndefined();
    expect(err.headers).toBeUndefined();
  });
});
