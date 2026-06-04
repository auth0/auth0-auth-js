import { describe, expect, test } from 'vitest';
import { StartLinkUserError } from './errors.js';

describe('StartLinkUserError', () => {
  test('sets name and code', () => {
    const error = new StartLinkUserError('link failed');

    expect(error.message).toBe('link failed');
    expect(error.name).toBe('StartLinkUserError');
    expect(error.code).toBe('start_link_user_error');
  });
});
