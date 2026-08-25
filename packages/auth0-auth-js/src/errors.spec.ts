import { describe, it, expect } from 'vitest';
import { TokenByCodeError } from './errors.js';

describe('ApiError statusCode/headers fields', () => {
  it('statusCode and headers are undefined by default', () => {
    const err = new TokenByCodeError('msg');
    expect(err.statusCode).toBeUndefined();
    expect(err.headers).toBeUndefined();
  });

  it('statusCode can be set post-construction', () => {
    const err = new TokenByCodeError('msg');
    err.statusCode = 401;
    expect(err.statusCode).toBe(401);
  });

  it('headers can be set post-construction', () => {
    const err = new TokenByCodeError('msg');
    err.headers = new Headers({ 'x-custom': 'val' });
    expect(err.headers.get('x-custom')).toBe('val');
  });
});
