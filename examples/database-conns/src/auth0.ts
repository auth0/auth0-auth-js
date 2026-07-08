import 'dotenv/config';
import { ServerClient } from '@auth0/auth0-server-js';

export const connection = process.env.AUTH0_DB_CONNECTION!;

export const auth0 = new ServerClient({
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  // ServerClient requires state and transaction stores at construction. The database operations
  // (signUp / changePassword) never read or write them, so no-op stores are sufficient
  // for this POC. A real app uses StatelessStateStore / StatefulStateStore and CookieTransactionStore.
  stateStore: {
    set: async () => {},
    get: async () => undefined,
    delete: async () => {},
  } as any,
  transactionStore: {
    create: async () => 'noop',
    read: async () => undefined,
    delete: async () => {},
  } as any,
});
