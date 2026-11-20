import { AbstractStore } from '../store/abstract-store.js';
import type { EncryptedStoreOptions } from '../types.js';
import type { PoppyGuestData, PoppyGuestStore } from './types.js';

/**
 * Abstract class that can be used to implement an encrypted guest store, using the 'A256CBC-HS512' encryption
 * algorithm.
 *
 * Extend this when you want the SDK's encryption but your own persistence (Redis, a database, and so on). For the
 * cookie-backed default, use `StatelessPoppyGuestStore`.
 *
 * Pass the `expiresAt` of the guest as the expiration to `this.encrypt`, and do not keep a guest after it. The SDK sets
 * `expiresAt` as the deadline of the guest.
 *
 * The store keeps a `PoppyGuestData`: `sub`, `sub_profile` (when the ID token has one) and `act`, which are the claims of
 * the ID token of the join with the names that the token gives them, and then `tokenSets`, `createdAt` and `expiresAt`.
 * Keep the record whole. `getContext()`, `getVisitor()` and `getGuestAccessToken()` delete a record that lacks `sub`,
 * `act.sub`, `act.poppy_sid`, `act.poppy_user_id` or a finite `expiresAt`. The check of a login only reads the guest.
 *
 * @beta
 * @category Session Stores & Cookies
 */
export abstract class AbstractPoppyGuestStore<TStoreOptions = unknown>
  extends AbstractStore<PoppyGuestData, TStoreOptions>
  implements PoppyGuestStore<TStoreOptions>
{
  constructor(options: EncryptedStoreOptions) {
    super(options);
  }
}
