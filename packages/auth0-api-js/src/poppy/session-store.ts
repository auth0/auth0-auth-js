import type { PoppySessionRecord } from '../types.js';

/**
 * An opt-in store of the Poppy Sessions your API has seen. With a store, the SDK runs the two Session checks of the
 * specification for you (sections 5.3 and 5.5): a known Session keeps its User ID and Agent ID, and a Session marked
 * as ended is refused.
 *
 * The SDK has no built-in store, no TTL and no clean-up. Extend this class on top of your own database. It is called
 * with the `key` of the verified Session, which is opaque: store it and read it back unchanged. You end a Session, and
 * remove old ones, in your own database, by setting `ended` on the record or deleting it.
 *
 * A `get` or `set` that throws fails the request: the SDK accepts no Session, and the error reaches your code as it is.
 *
 * In a Session from the `Poppy-Session` header, the agent chooses the `userId` and the `poppyAgentId` of the record.
 * The specification sets no format for them, so the SDK enforces no short limit: only the 16,384 characters of the
 * whole Session JWT bound them, and each can be several KB. Size the columns of your table for that.
 *
 * @example
 * ```typescript
 * class DbPoppySessionStore extends PoppySessionStore {
 *   constructor(private readonly db: Db) {
 *     super();
 *   }
 *
 *   get(key: string) {
 *     return this.db.poppySessions.find(key);
 *   }
 *
 *   set(key: string, record: PoppySessionRecord) {
 *     return this.db.poppySessions.insertIfAbsent(key, record);
 *   }
 * }
 * ```
 *
 * @beta
 * @category Poppy
 */
export abstract class PoppySessionStore {
  /**
   * Returns the record stored under `key`, or `undefined` or `null` when there is none. Both mean the same, and `null`
   * is in the type because Prisma `findUnique`, MongoDB `findOne` and Redis `GET` return it for no record.
   */
  abstract get(key: string): Promise<PoppySessionRecord | null | undefined>;

  /**
   * Stores `record` under `key` only if there is no record for `key` yet, and resolves to the record that is stored
   * afterwards: `record` itself, or the one that was already there. It must never overwrite.
   *
   * Two first requests of a Session can arrive together, so both can call `set` for the same `key`. The store keeps
   * the first record, and the SDK compares the Session with the record `set` resolves to.
   */
  abstract set(key: string, record: PoppySessionRecord): Promise<PoppySessionRecord>;
}
