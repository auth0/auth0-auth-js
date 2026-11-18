import { errors } from 'jose';
import { isSessionExpiryReached } from '../state/utils.js';
import type { TokenSet } from '../types.js';
import type { PoppySessionAct } from './claims.js';
import type { PoppyGuestData, PoppyGuestStore } from './types.js';

/**
 * @internal
 * A record from the guest store that has the members that a read uses.
 */
export type StoredGuest = PoppyGuestData & { act: PoppySessionAct };

/**
 * @internal
 * Whether the access token of a guest can still be used: it is good until its `expiresAt`, and a token with no token set
 * or no expiry (`undefined`, `null`, `NaN`) fails the test. `getGuestAccessToken()` and the guard of a login both ask
 * this, so a guest is renewed exactly when `getGuestAccessToken()` gives nothing.
 */
export function guestTokenIsUsable(tokenSet: TokenSet | undefined): boolean {
  // A custom guest store can give back a list with a hole in it, so the first member is tested as a value, not a type.
  return !!tokenSet && tokenSet.expiresAt > Date.now() / 1000;
}

/**
 * @internal
 * What the guest store holds for a browser:
 * - `none`: nothing, or a value that cannot be opened.
 * - `ended`: a guest that is over. Its deadline is 30 seconds away or less, its encrypted value has ended, or its record
 *   lacks a member that a read uses. It must be treated as no guest, and it is for the caller to delete it.
 * - `active`: a guest that has not ended.
 */
export type GuestRead = { status: 'none' } | { status: 'ended' } | { status: 'active'; guest: StoredGuest };

// Whether a record from the guest store has the members that a read uses. The SDK always writes them, but a custom
// guest store can give back anything, and a record that lacks one is not trusted. `expiresAt` must be a finite number:
// the check of the deadline is false for `NaN`, so a guest with that deadline would never end.
function hasGuestMembers(guest: PoppyGuestData): guest is StoredGuest {
  const { sub, act, expiresAt } = guest;

  return (
    Number.isFinite(expiresAt) &&
    typeof sub === 'string' &&
    typeof act?.sub === 'string' &&
    typeof act.poppy_sid === 'string' &&
    typeof act.poppy_user_id === 'string'
  );
}

/**
 * @internal
 * Reads the guest of the browser. The guest store does not check `expiresAt`: it gives the record back until the
 * encrypted value ends, and 15 seconds after that, and then it throws `JWTExpired`. A guest must never outlive its
 * deadline, so the checks are made here. Both the read of the visitor and the guard of a login use this, so they agree on
 * which guest is there.
 *
 * It deletes nothing. `JWTExpired`, a record that lacks a member and a deadline that is 30 seconds away or less all give
 * `ended`. Any other error of the store goes to the caller: a store that fails is never read as empty.
 */
export async function readGuest<TStoreOptions>(
  guestStore: PoppyGuestStore<TStoreOptions>,
  identifier: string,
  storeOptions?: TStoreOptions
): Promise<GuestRead> {
  let guest: PoppyGuestData | undefined;

  try {
    guest = await guestStore.get(identifier, storeOptions);
  } catch (error) {
    if (error instanceof errors.JWTExpired) {
      return { status: 'ended' };
    }

    throw error;
  }

  if (!guest) {
    return { status: 'none' };
  }

  // `isSessionExpiryReached` is true when `expiresAt` is 30 seconds away or less. The deadline is a number, never a
  // truthy value: one that is 0 is a time in the past.
  if (!hasGuestMembers(guest) || isSessionExpiryReached(guest.expiresAt)) {
    return { status: 'ended' };
  }

  return { status: 'active', guest };
}
