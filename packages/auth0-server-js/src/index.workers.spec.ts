import { test, expect } from 'vitest';
import {
  ServerClient,
  AbstractStateStore,
  AbstractTransactionStore,
} from '../dist/index.js';
import type { StateData, TransactionData, LogoutTokenClaims } from '../dist/index.js';

class TestStateStore extends AbstractStateStore {
  readonly #data = new Map<string, StateData>();

  set(identifier: string, value: StateData): Promise<void> {
    this.#data.set(identifier, value);
    return Promise.resolve();
  }

  get(identifier: string): Promise<StateData | undefined> {
    return Promise.resolve(this.#data.get(identifier));
  }

  delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);
    return Promise.resolve();
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  deleteByLogoutToken(_claims: LogoutTokenClaims): Promise<void> {
    return Promise.resolve();
  }
}

class TestTransactionStore extends AbstractTransactionStore {
  readonly #data = new Map<string, TransactionData>();

  set(identifier: string, value: TransactionData): Promise<void> {
    this.#data.set(identifier, value);
    return Promise.resolve();
  }

  get(identifier: string): Promise<TransactionData | undefined> {
    return Promise.resolve(this.#data.get(identifier));
  }

  delete(identifier: string): Promise<void> {
    this.#data.delete(identifier);
    return Promise.resolve();
  }
}

test('ServerClient can be instantiated', () => {
  const client = new ServerClient({
    domain: 'example.auth0.com',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    stateStore: new TestStateStore({ secret: 'secret-that-is-at-least-32-characters' }),
    transactionStore: new TestTransactionStore({ secret: 'secret-that-is-at-least-32-characters' }),
  });

  expect(client).toBeDefined();
});
