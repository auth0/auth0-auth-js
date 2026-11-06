import { describe, expect, expectTypeOf, test } from 'vitest';

import { MemoryStore, rejectionOf } from '../test-utils/poppy.js';
import type { PoppySession, PoppySessionRecord } from '../types.js';
import { InvalidSessionError, SessionEndedError } from './errors.js';
import { checkSessionRecord } from './session-record.js';
import { PoppySessionStore } from './session-store.js';

const CIMD_URL = 'https://agent.example/agent.json';
const KEY = 'TCKalJy8Oz7hl1YTKAJt86LQcaiaLsYmFX-cLwiaJ4c';
const USER_ID = 'usr_test';
const OTHER_USER_ID = 'usr_other';
const AGENT_ID = 'travel';
const OTHER_AGENT_ID = 'food';

// The default texts of the two errors, word for word. They are fixed: no User ID, Agent ID or key is in them.
const SESSION_MISMATCH_MESSAGE = "The Session JWT's User ID or Agent ID doesn't match the Session.";
const SESSION_ENDED_MESSAGE = 'The Session has ended. Start a new Session with a new sid and send the request again.';

/** A verified Session as the pipeline builds it. `agent` is replaced as a whole. */
function sessionOf(overrides: Partial<PoppySession> = {}): PoppySession {
  return {
    sessionId: 'Yx2b7Qd_Kp8mR3vT1nWc4A',
    key: KEY,
    userId: USER_ID,
    agent: { cimdUrl: CIMD_URL },
    state: 'signed_out',
    source: 'header',
    ...overrides,
  };
}

/** A store whose `get` and `set` are the functions given, to make the answers a real store would not give. */
class ScriptedStore extends PoppySessionStore {
  readonly getCalls: string[] = [];
  readonly setCalls: Array<{ key: string; record: PoppySessionRecord }> = [];

  constructor(
    private readonly onGet: (key: string) => Promise<PoppySessionRecord | undefined>,
    private readonly onSet: (key: string, record: PoppySessionRecord) => Promise<PoppySessionRecord>
  ) {
    super();
  }

  get(key: string): Promise<PoppySessionRecord | undefined> {
    this.getCalls.push(key);
    return this.onGet(key);
  }

  set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord> {
    this.setCalls.push({ key, record });
    return this.onSet(key, record);
  }
}

function expectSessionMismatch(error: unknown): void {
  expect(error).toBeInstanceOf(InvalidSessionError);
  const mismatch = error as InvalidSessionError;
  expect(mismatch.reason).toBe('session_mismatch');
  expect(mismatch.code).toBe('invalid_session');
  expect(mismatch.statusCode).toBe(400);
  expect(mismatch.message).toBe(SESSION_MISMATCH_MESSAGE);
}

function expectSessionEnded(error: unknown): void {
  expect(error).toBeInstanceOf(SessionEndedError);
  const ended = error as SessionEndedError;
  expect(ended.code).toBe('session_ended');
  expect(ended.statusCode).toBe(400);
  expect(ended.message).toBe(SESSION_ENDED_MESSAGE);
}

describe('checkSessionRecord', () => {
  describe('a key the store does not know', () => {
    test('saves the User ID under the key', async () => {
      const store = new MemoryStore();

      await expect(checkSessionRecord(store, sessionOf())).resolves.toBeUndefined();

      expect(store.getCalls).toEqual([KEY]);
      // `toStrictEqual`, so a `poppyAgentId: undefined` member would fail.
      expect(store.setCalls).toStrictEqual([{ key: KEY, record: { userId: USER_ID } }]);
      expect(store.records.get(KEY)).toStrictEqual({ userId: USER_ID });
    });

    test('saves the Agent ID too, when the Session has one', async () => {
      const store = new MemoryStore();
      const session = sessionOf({ agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } });

      await expect(checkSessionRecord(store, session)).resolves.toBeUndefined();

      expect(store.setCalls).toStrictEqual([{ key: KEY, record: { userId: USER_ID, poppyAgentId: AGENT_ID } }]);
    });

    test('reads the record of the key of the Session, and no other', async () => {
      const store = new MemoryStore();
      store.records.set('another-key', { userId: OTHER_USER_ID });

      await checkSessionRecord(store, sessionOf());

      expect(store.getCalls).toEqual([KEY]);
      expect(store.setCalls.map((call) => call.key)).toEqual([KEY]);
    });

    test('reads a null from get as no record, and saves the User ID', async () => {
      // A database library often returns null for no row, though the type says undefined.
      const store = new ScriptedStore(
        () => Promise.resolve(null as unknown as undefined),
        (_key, record) => Promise.resolve(record)
      );

      await expect(checkSessionRecord(store, sessionOf())).resolves.toBeUndefined();

      expect(store.setCalls).toStrictEqual([{ key: KEY, record: { userId: USER_ID } }]);
    });
  });

  describe('a key the store knows', () => {
    test.each([
      { name: 'a User ID', record: { userId: USER_ID }, agent: { cimdUrl: CIMD_URL } },
      {
        name: 'a User ID and an Agent ID',
        record: { userId: USER_ID, poppyAgentId: AGENT_ID },
        agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
      },
      { name: 'ended set to false', record: { userId: USER_ID, ended: false }, agent: { cimdUrl: CIMD_URL } },
    ])('continues a Session whose record has $name, and does not save it again', async ({ record, agent }) => {
      const store = new MemoryStore();
      store.records.set(KEY, record);

      await expect(checkSessionRecord(store, sessionOf({ agent }))).resolves.toBeUndefined();

      expect(store.getCalls).toEqual([KEY]);
      expect(store.setCalls).toEqual([]);
      expect(store.records.get(KEY)).toBe(record);
    });

    test('reads a record with no Agent ID as one with none, whether the database says undefined or null', async () => {
      // A database often returns NULL for a column that has no value, though the type says `undefined`.
      const withNull = { userId: USER_ID, poppyAgentId: null } as unknown as PoppySessionRecord;
      const withUndefined = { userId: USER_ID, poppyAgentId: undefined };

      for (const record of [withNull, withUndefined]) {
        const store = new MemoryStore();
        store.records.set(KEY, record);

        await expect(checkSessionRecord(store, sessionOf())).resolves.toBeUndefined();
      }
    });

    test.each([
      { name: 'another User ID', record: { userId: OTHER_USER_ID }, agent: { cimdUrl: CIMD_URL } },
      {
        name: 'another User ID, and the same Agent ID',
        record: { userId: OTHER_USER_ID, poppyAgentId: AGENT_ID },
        agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
      },
      {
        name: 'another Agent ID',
        record: { userId: USER_ID, poppyAgentId: OTHER_AGENT_ID },
        agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
      },
      {
        name: 'an Agent ID, where the Session has none',
        record: { userId: USER_ID, poppyAgentId: AGENT_ID },
        agent: { cimdUrl: CIMD_URL },
      },
      {
        name: 'no Agent ID, where the Session has one',
        record: { userId: USER_ID },
        agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
      },
      {
        name: 'another User ID and another Agent ID',
        record: { userId: OTHER_USER_ID, poppyAgentId: OTHER_AGENT_ID },
        agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID },
      },
    ])('refuses a Session whose record has $name with session_mismatch', async ({ record, agent }) => {
      const store = new MemoryStore();
      store.records.set(KEY, record);

      expectSessionMismatch(await rejectionOf(checkSessionRecord(store, sessionOf({ agent }))));

      // A mismatch never overwrites the record.
      expect(store.setCalls).toEqual([]);
      expect(store.records.get(KEY)).toBe(record);
    });

    test('compares the User ID exactly, with no case folding or trimming', async () => {
      for (const userId of ['USR_TEST', ' usr_test', 'usr_test ']) {
        const store = new MemoryStore();
        store.records.set(KEY, { userId: USER_ID });

        expectSessionMismatch(await rejectionOf(checkSessionRecord(store, sessionOf({ userId }))));
      }
    });
  });

  describe('a Session that has ended', () => {
    test.each([
      { name: 'true', ended: true },
      // A raw SQL row gives 1 for a true flag. Any truthy value ends the Session, so the check fails closed.
      { name: '1', ended: 1 as unknown as boolean },
    ])('is refused with SessionEndedError when ended is $name', async ({ ended }) => {
      const store = new MemoryStore();
      store.records.set(KEY, { userId: USER_ID, ended });

      expectSessionEnded(await rejectionOf(checkSessionRecord(store, sessionOf())));

      expect(store.setCalls).toEqual([]);
    });

    test('is refused with SessionEndedError, not session_mismatch, when the User ID is another one', async () => {
      const store = new MemoryStore();
      store.records.set(KEY, { userId: OTHER_USER_ID, poppyAgentId: OTHER_AGENT_ID, ended: true });
      const session = sessionOf({ agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } });

      expectSessionEnded(await rejectionOf(checkSessionRecord(store, session)));
    });

    test('is not ended when ended is false, and a mismatch is then a mismatch', async () => {
      const store = new MemoryStore();
      store.records.set(KEY, { userId: OTHER_USER_ID, ended: false });

      expectSessionMismatch(await rejectionOf(checkSessionRecord(store, sessionOf())));
    });
  });

  describe('a store that fails', () => {
    test('rejects with the error of get, as it is, and saves nothing', async () => {
      const failure = new Error('db down');
      const store = new ScriptedStore(
        () => Promise.reject(failure),
        () => Promise.reject(new Error('set must not be called'))
      );

      await expect(checkSessionRecord(store, sessionOf())).rejects.toBe(failure);

      expect(store.getCalls).toEqual([KEY]);
      expect(store.setCalls).toEqual([]);
    });

    test('rejects with the error of get when get throws at once, as it is', async () => {
      const failure = new Error('db down');
      const store = new ScriptedStore(
        () => {
          throw failure;
        },
        () => Promise.resolve({ userId: USER_ID })
      );

      await expect(checkSessionRecord(store, sessionOf())).rejects.toBe(failure);
    });

    test('rejects with the error of set, as it is', async () => {
      const failure = new Error('db down');
      const store = new ScriptedStore(
        () => Promise.resolve(undefined),
        () => Promise.reject(failure)
      );

      await expect(checkSessionRecord(store, sessionOf())).rejects.toBe(failure);

      expect(store.setCalls).toEqual([{ key: KEY, record: { userId: USER_ID } }]);
    });
  });

  describe('two first requests of one Session, that arrive together', () => {
    test('refuses the one whose User ID lost the race, when set resolves to the record of the winner', async () => {
      const winner: PoppySessionRecord = { userId: OTHER_USER_ID };
      const store = new ScriptedStore(
        () => Promise.resolve(undefined),
        () => Promise.resolve(winner)
      );

      expectSessionMismatch(await rejectionOf(checkSessionRecord(store, sessionOf())));
    });

    test('refuses the one that lost the race when get returned null, as it does for undefined', async () => {
      const store = new ScriptedStore(
        () => Promise.resolve(null as unknown as undefined),
        () => Promise.resolve({ userId: OTHER_USER_ID })
      );

      expectSessionMismatch(await rejectionOf(checkSessionRecord(store, sessionOf())));
    });

    test('refuses the one whose Agent ID lost the race', async () => {
      const winner: PoppySessionRecord = { userId: USER_ID, poppyAgentId: OTHER_AGENT_ID };
      const store = new ScriptedStore(
        () => Promise.resolve(undefined),
        () => Promise.resolve(winner)
      );
      const session = sessionOf({ agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } });

      expectSessionMismatch(await rejectionOf(checkSessionRecord(store, session)));
    });

    test('accepts the one that agrees with the record of the winner', async () => {
      const winner: PoppySessionRecord = { userId: USER_ID, poppyAgentId: AGENT_ID };
      const store = new ScriptedStore(
        () => Promise.resolve(undefined),
        () => Promise.resolve({ ...winner })
      );
      const session = sessionOf({ agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } });

      await expect(checkSessionRecord(store, session)).resolves.toBeUndefined();
    });

    test('refuses with SessionEndedError when set resolves to a record that has ended', async () => {
      const store = new ScriptedStore(
        () => Promise.resolve(undefined),
        () => Promise.resolve({ userId: OTHER_USER_ID, ended: true })
      );

      expectSessionEnded(await rejectionOf(checkSessionRecord(store, sessionOf())));
    });

    test('lets two real first requests with the same User ID both through, and saves one record', async () => {
      const store = new MemoryStore();

      await Promise.all([checkSessionRecord(store, sessionOf()), checkSessionRecord(store, sessionOf())]);

      expect(store.records.size).toBe(1);
      expect(store.records.get(KEY)).toStrictEqual({ userId: USER_ID });
    });

    test('refuses the second of two real first requests when its User ID is another one', async () => {
      const store = new MemoryStore();

      // Both calls read no record before either one saves, as in a real database. The store keeps the first record.
      const settled = await Promise.allSettled([
        checkSessionRecord(store, sessionOf()),
        checkSessionRecord(store, sessionOf({ userId: OTHER_USER_ID })),
      ]);

      expect(settled[0]?.status).toBe('fulfilled');
      expect(settled[1]?.status).toBe('rejected');
      expectSessionMismatch((settled[1] as PromiseRejectedResult).reason);
      expect(store.setCalls).toHaveLength(2);
      expect(store.records.get(KEY)).toStrictEqual({ userId: USER_ID });
    });
  });

  test('does not change the Session', async () => {
    const session = sessionOf({ agent: { cimdUrl: CIMD_URL, poppyAgentId: AGENT_ID } });
    const before = structuredClone(session);

    await checkSessionRecord(new MemoryStore(), session);

    expect(session).toStrictEqual(before);
  });
});

describe('PoppySessionStore | the return type of get', () => {
  // Prisma `findUnique`, MongoDB `findOne` and Redis `GET` give `null` for no record. These stores compile as they are,
  // with no cast, and `npm run typecheck` checks that.
  abstract class MapStore extends PoppySessionStore {
    readonly records = new Map<string, PoppySessionRecord>();

    async set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord> {
      const stored = this.records.get(key) ?? record;
      this.records.set(key, stored);
      return stored;
    }
  }

  class NullStore extends MapStore {
    async get(key: string): Promise<PoppySessionRecord | null> {
      return this.records.get(key) ?? null;
    }
  }

  class UndefinedStore extends MapStore {
    async get(key: string): Promise<PoppySessionRecord | undefined> {
      return this.records.get(key);
    }
  }

  test('says that a store may return null, undefined or a record', () => {
    expectTypeOf<PoppySessionStore['get']>().returns.resolves.toEqualTypeOf<PoppySessionRecord | null | undefined>();
    expectTypeOf<NullStore['get']>().returns.resolves.toEqualTypeOf<PoppySessionRecord | null>();
    expectTypeOf<UndefinedStore['get']>().returns.resolves.toEqualTypeOf<PoppySessionRecord | undefined>();
    expect(typeof PoppySessionStore).toBe('function');
  });

  test.each([
    { name: 'null', store: () => new NullStore() },
    { name: 'undefined', store: () => new UndefinedStore() },
  ])('saves a new Session, and continues it, with a store whose get returns $name for no record', async ({ store }) => {
    const used = store();

    await checkSessionRecord(used, sessionOf());
    await checkSessionRecord(used, sessionOf());

    expect(used.records.get(KEY)).toStrictEqual({ userId: USER_ID });
    expectSessionMismatch(await rejectionOf(checkSessionRecord(used, sessionOf({ userId: OTHER_USER_ID }))));
  });
});
