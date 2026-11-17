import type { PoppySession, PoppySessionRecord } from '../types.js';
import { InvalidSessionError, SessionEndedError } from './errors.js';
import type { PoppySessionStore } from './session-store.js';

// Spec: https://personalagentprotocol.org/docs/1.0/spec, section 5.3 (step 4) and section 5.5.

/**
 * Checks a verified Session against its record in the store, and saves the record of a new Session. A record that has
 * ended gives `SessionEndedError`, before the User ID is compared.
 *
 * The key of the Session holds the agent, the Session ID and the User ID, so the record that the store finds is the
 * record of that combination, and the User ID can differ only for a store that keeps records under another key. A record
 * with another User ID gives `session_mismatch`, as a safety check. The Agent ID is kept with the record when the Session
 * starts, and is not compared afterwards: Poppy 1.0 finds a Session by `client_id`, `sid` and User ID only. An error of
 * the store is not caught, so the request fails.
 */
export async function checkSessionRecord(store: PoppySessionStore, session: PoppySession): Promise<void> {
  const { userId } = session;
  const { poppyAgentId } = session.agent;

  // A database library often gives `null` for no row, so that is no record too.
  let record = (await store.get(session.key)) ?? undefined;
  if (record === undefined) {
    // No `poppyAgentId` member when there is none. `set` never overwrites: it resolves to the stored record, which
    // another first request may have saved before this one, so that is the record to compare with.
    const created: PoppySessionRecord = poppyAgentId === undefined ? { userId } : { userId, poppyAgentId };
    record = await store.set(session.key, created);
  }

  // A truthy read, not `=== true`: a raw SQL row gives `1`, and that must end the Session too (fail closed).
  if (record.ended) {
    throw new SessionEndedError();
  }
  if (record.userId !== userId) {
    throw new InvalidSessionError('session_mismatch');
  }
}
