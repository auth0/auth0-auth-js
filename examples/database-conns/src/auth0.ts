import 'dotenv/config';
import {
  ServerClient,
  type StateStore,
  type TransactionStore,
} from '@auth0/auth0-server-js';

/** Fail fast with a clear message instead of passing `undefined` cast to string into the SDK. */
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}. Copy .env.example to .env and fill it in.`);
  }
  return value;
}

const config = {
  domain: requireEnv('AUTH0_DOMAIN'),
  clientId: requireEnv('AUTH0_CLIENT_ID'),
  clientSecret: requireEnv('AUTH0_CLIENT_SECRET'),
  connection: requireEnv('AUTH0_DB_CONNECTION'),
};

export const connection = config.connection;

// ServerClient requires state and transaction stores at construction. The database operations
// (signUp / changePassword) never read or write them, so no-op stores are sufficient for this
// POC. A real app uses StatelessStateStore / StatefulStateStore and CookieTransactionStore.
// The stores are typed with the real SDK interfaces (not `as any`) so a signature change in the
// store contract surfaces as a compile error here instead of silently passing.
const noopStateStore: StateStore = {
  set: async () => {},
  get: async () => undefined,
  delete: async () => {},
  deleteByLogoutToken: async () => {},
};

const noopTransactionStore: TransactionStore = {
  set: async () => {},
  get: async () => undefined,
  delete: async () => {},
};

export const auth0 = new ServerClient({
  domain: config.domain,
  clientId: config.clientId,
  clientSecret: config.clientSecret,
  stateStore: noopStateStore,
  transactionStore: noopTransactionStore,
});
