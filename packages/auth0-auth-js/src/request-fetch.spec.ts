import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { createCapturingFetch } from './request-fetch.js';

const server = setupServer(
  http.post('https://auth0.local/custom/token', () =>
    HttpResponse.json({ access_token: 'tok123', token_type: 'Bearer', expires_in: 3600 })
  )
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterAll(() => server.close());
beforeEach(() => server.resetHandlers());

describe('createCapturingFetch', () => {
  describe('types', () => {
    it('returns object with getCapturedResponse method', () => {
      const cf = createCapturingFetch(fetch);
      expect(typeof cf).toBe('function');
      expect(typeof cf.getCapturedResponse).toBe('function');
    });
  });

  describe('capture behavior', () => {
    it('stores cloned response — caller gets fresh body', async () => {
      const cf = createCapturingFetch(fetch);
      await cf('https://auth0.local/custom/token', { method: 'POST' });
      const captured = cf.getCapturedResponse();

      expect(captured).toBeInstanceOf(Response);
      expect(captured!.bodyUsed).toBe(false);
      const body = await captured!.json();
      expect(body).toHaveProperty('access_token');
    });

    it('two instances do not share state', async () => {
      const cf1 = createCapturingFetch(fetch);
      const cf2 = createCapturingFetch(fetch);
      await cf1('https://auth0.local/custom/token', { method: 'POST' });

      expect(cf1.getCapturedResponse()).toBeInstanceOf(Response);
      expect(cf2.getCapturedResponse()).toBeUndefined();
    });

    it('getCapturedResponse returns undefined before first call', () => {
      const cf = createCapturingFetch(fetch);
      expect(cf.getCapturedResponse()).toBeUndefined();
    });

    it('cloned body is readable after wrapper returns', async () => {
      const cf = createCapturingFetch(fetch);
      const originalResponse = await cf('https://auth0.local/custom/token', { method: 'POST' });

      // Consume original
      await originalResponse.json();
      const captured = cf.getCapturedResponse()!;

      expect(originalResponse.bodyUsed).toBe(true);
      expect(captured.bodyUsed).toBe(false);
      const clonedBody = await captured.json();
      expect(clonedBody.access_token).toBe('tok123');
    });
  });

  describe('negative cases', () => {
    it('getCapturedResponse returns undefined before any fetch call', () => {
      const cf = createCapturingFetch(fetch);
      expect(cf.getCapturedResponse()).toBeUndefined();
    });
  });
});
