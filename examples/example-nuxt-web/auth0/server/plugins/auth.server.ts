import { ServerClient } from '@auth0/auth0-server-js';
import { defineNitroPlugin } from 'nitropack/dist/runtime/plugin';
import { CookieTransactionStore } from '~/store/cookie-transaction-store';
import { StatelessStateStore } from '~/store/stateless-state-store';

declare module 'h3' {
  interface H3EventContext {
    auth0Client: ServerClient<{ event: H3Event }>;
  }
}

export default defineNitroPlugin((nitroApp) => {
  const config = useRuntimeConfig();
  const options: any = config.auth0;

  const callbackPath = '/auth/callback';
  const redirectUri = new URL(callbackPath, options.appBaseUrl);
  
  const auth0Client = new ServerClient({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationParams: {
      redirect_uri: redirectUri.toString(),
    },
    transactionStore: new CookieTransactionStore(),
    stateStore: new StatelessStateStore({
      secret: options.sessionSecret,
    }),
  });

  nitroApp.hooks.hook('request', async (event) => {
    // TODO: See if there are alternative / better ways to set auth0Client, auth0ClientOptions and user
    event.context.auth0Client = auth0Client;
    event.context.auth0ClientOptions = {
        appBaseUrl: options.appBaseUrl,
    };
  });
});
