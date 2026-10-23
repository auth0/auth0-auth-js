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
    const update = vi.fn<(id: string, data: StateData) => Promise<boolean>>().mockResolvedValue(true);
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
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
    const update = vi.fn<(id: string, data: StateData) => Promise<boolean>>().mockResolvedValue(false);
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
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const backingStore = {
      set,
      get: vi.fn().mockResolvedValue(makeStateData()),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-abc'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(set).toHaveBeenCalledWith('session-abc', expect.anything());
    expect(handler.setCookie).toHaveBeenCalled();
    expect(backingStore.get).toHaveBeenCalledWith('session-abc');
  });

  test('does not write the row or cookie when the store has no update() and the row is gone (concurrent logout)', async () => {
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const get = vi.fn<(id: string) => Promise<StateData | undefined>>().mockResolvedValue(undefined);
    const backingStore = {
      set,
      get,
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-gone'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(get).toHaveBeenCalledWith('session-gone');
    expect(set).not.toHaveBeenCalled();
    expect(handler.setCookie).not.toHaveBeenCalled();
  });

  test('reads the row before writing it when the store has no update()', async () => {
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const get = vi.fn<(id: string) => Promise<StateData | undefined>>().mockResolvedValue(makeStateData());
    const backingStore = {
      set,
      get,
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-abc'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(get.mock.invocationCallOrder[0]).toBeLessThan(set.mock.invocationCallOrder[0]!);
  });

  test('still writes a fresh login when the cookie is stale and the store has no update()', async () => {
    // The cookie points at a row that no longer exists. A login must not be treated as a rolling save.
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const get = vi.fn<(id: string) => Promise<StateData | undefined>>().mockResolvedValue(undefined);
    const del = vi.fn<(id: string) => Promise<void>>().mockResolvedValue(undefined);
    const backingStore = {
      set,
      get,
      delete: del,
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('stale-session-id'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), true);

    expect(get).not.toHaveBeenCalled();
    expect(del).toHaveBeenCalledWith('stale-session-id');
    expect(set).toHaveBeenCalledOnce();
    const [calledId] = set.mock.calls[0] as [string, StateData];
    expect(calledId).not.toBe('stale-session-id');
    expect(handler.setCookie).toHaveBeenCalled();
  });

  test('does not read the row when no session cookie exists and the store has no update()', async () => {
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const get = vi.fn<(id: string) => Promise<StateData | undefined>>();
    const backingStore = {
      set,
      get,
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { handler } = makeCookieHandler(); // no pre-existing cookie

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);
    await store.set(IDENTIFIER, makeStateData(), false);

    expect(get).not.toHaveBeenCalled();
    expect(set).toHaveBeenCalledOnce();
    expect(handler.setCookie).toHaveBeenCalled();
  });

  test('passes a get() failure to the caller and writes nothing when the store has no update()', async () => {
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const get = vi
      .fn<(id: string) => Promise<StateData | undefined>>()
      .mockRejectedValue(new Error('store unavailable'));
    const backingStore = {
      set,
      get,
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-abc'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);

    await expect(store.set(IDENTIFIER, makeStateData(), false)).rejects.toThrow('store unavailable');
    expect(set).not.toHaveBeenCalled();
    expect(handler.setCookie).not.toHaveBeenCalled();
  });

  test('passes an update() failure to the caller and does not write the cookie', async () => {
    const update = vi
      .fn<(id: string, data: StateData) => Promise<boolean>>()
      .mockRejectedValue(new Error('store unavailable'));
    const backingStore = {
      set: vi.fn(),
      update,
      get: vi.fn(),
      delete: vi.fn(),
      deleteByLogoutToken: vi.fn(),
    } as unknown as SessionStore<undefined>;

    const { cookies, handler } = makeCookieHandler();
    cookies.set(IDENTIFIER, await makeSessionCookie('session-abc'));

    const store = new StatefulStateStore({ secret: SECRET, store: backingStore }, handler);

    await expect(store.set(IDENTIFIER, makeStateData(), false)).rejects.toThrow('store unavailable');
    expect(handler.setCookie).not.toHaveBeenCalled();
  });

  test('uses set() instead of update() for a fresh login (removeIfExists=true)', async () => {
    const update = vi.fn<(id: string, data: StateData) => Promise<boolean>>().mockResolvedValue(true);
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
    const backingStore = {
      set,
      update,
      get: vi.fn(),
      delete: vi.fn<(id: string) => Promise<void>>().mockResolvedValue(undefined),
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
    const update = vi.fn<(id: string, data: StateData) => Promise<boolean>>().mockResolvedValue(true);
    const set = vi.fn<(id: string, data: StateData) => Promise<void>>();
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
