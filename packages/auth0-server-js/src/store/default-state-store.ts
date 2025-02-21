import { StateData, StateStore, } from '../types.js';

/**
 * Default, in-memory, state store.
 */
export class DefaultStateStore implements StateStore {
  data = new Map<string, StateData>();

  delete(identifier: string): Promise<void> {
    this.data.delete(identifier);

    return Promise.resolve();
  }
  set(identifier: string, transactionData: StateData): Promise<void> {
    this.data.set(identifier, transactionData);

    return Promise.resolve();
  }
  get(identifier: string): Promise<StateData | undefined> {
    return Promise.resolve(this.data.get(identifier));
  }
}
