import { describe, expect, test, vi } from 'vitest';
import { StatefulStateStore } from './stateful-state-store.js';
import { encrypt } from '../test-utils/encryption.js';
import type { CookieHandler } from './cookie-handler.js';
import type { StateData, SessionStore } from '../types.js';

const SECRET = '<test-secret-long-enough-32-bytes!>';
const IDENTIFIER = 'appSession';

function makeStateData(): StateData {
  return {
    user: undefined,
    idToken: undefined,
    refreshToken: undefined,
    tokenSets: [],
    internal: { sid: 'sid-test', createdAt: Math.floor(Date.now() / 1000) },
  };
}

function makeCookieHandler() {
  const cookies = new Map<string, string>();
  const handler: CookieHandler<undefined> = {
    getCookie: vi.fn((name: string) => cookies.get(name)),
    getCookies: vi.fn(() => Object.fromEntries(cookies)),
    setCookie: vi.fn((name: string, value: string) => {
      cookies.set(name, value);
    }),
    deleteCookie: vi.fn((name: string) => {
      cookies.delete(name);
    }),
  };
  return { cookies, handler };
}

async function makeSessionCookie(sessionId: string): Promise<string> {
  return encrypt({ id: sessionId }, SECRET, IDENTIFIER, Date.now() / 1000 + 3600);
}

describe('SessionStore.update() — optional atomic fast-path', () => {
  test('calls update() instead of set() when the store supports it and the session exists', async () => {
    const update = vi.fn<[string, StateData], Promise<boolean>>().mockResolvedValue(true);
    const set = vi.fn<[string, StateData], Promise<void>>();
    const backingStore = {
      set,
      update,
      get: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-abc'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    const stateData = makeStateData();
    await store.set(IDENTIFIER, stateData, false);

    expect(update).toHaveBeenCalledOnce();
    expect(update).toHaveBeenCalledWith('session-abc', stateData);
    expect(set).not.toHaveBeenCalled();
    expect(handler.setCookie).toHaveBeenCalled();
  });

  test('does not write the cookie when update() returns false (row gone — concurrent logout)', async () => {
    const update = vi.fn<[string, StateData], Promise<boolean>>().mockResolvedValue(false);
    const backingStore = {
      set: vi.fn(),
      update,
      get: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-xyz'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(update).toHaveBeenCalledOnce();
    expect(handler.setCookie).not.toHaveBeenCalled();
  });

  test('falls back to set() when the store does not implement update()', async () => {
    const set = vi.fn<[string, StateData], Promise<void>>();
    const backingStore = {
      set,
      get: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-abc'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(set).toHaveBeenCalledWith('session-abc', expect.anything());
    expect(handler.setCookie).toHaveBeenCalled();
  });

  test('uses set() instead of update() for a fresh login (removeIfExists=true)', async () => {
    const update = vi.fn<[string, StateData], Promise<boolean>>().mockResolvedValue(true);
    const set = vi.fn<[string, StateData], Promise<void>>();
    const backingStore = {
      set,
      update,
      get: vi.fn(),
      delete: vi.fn<[string], Promise<void>>().mockResolvedValue(undefined),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('old-session-id'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), true);

    expect(update).not.toHaveBeenCalled();
    expect(set).toHaveBeenCalledOnce();
    // set() is called with a newly-generated session ID, not the old one
    const [calledId] = set.mock.calls[0] as [string, StateData];
    expect(calledId).not.toBe('old-session-id');
  });

  test('uses set() instead of update() when no session cookie exists (brand-new session)', async () => {
    const update = vi.fn<[string, StateData], Promise<boolean>>().mockResolvedValue(true);
    const set = vi.fn<[string, StateData], Promise<void>>();
    const backingStore = {
      set,
      update,
      get: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { handler } = makeCookieHandler(); // no pre-existing cookie

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(update).not.toHaveBeenCalled();
    expect(set).toHaveBeenCalledOnce();
    expect(handler.setCookie).toHaveBeenCalled();
  });
});
