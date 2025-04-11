import type { StartInteractiveLoginOptions } from '@auth0/auth0-server-js';

export const useAuth0Client = () => {
  const nuxtApp = useNuxtApp();
  const h3Event = nuxtApp.ssrContext!.event;
  const auth0Client = h3Event?.context.auth0Client;

  // TODO: Expose all methods here without the StoreOptions argument
  // Doing so, we keep the complexity away from the user and simplify interacting with the SDK in a Nuxt application
  return {
    startInteractiveLogin: (options?: StartInteractiveLoginOptions) =>
      auth0Client?.startInteractiveLogin(options, { event: h3Event }),
    completeInteractiveLogin: (url: URL) =>
      auth0Client?.completeInteractiveLogin(url, { event: h3Event }),
    getUser: () => auth0Client?.getUser({ event: h3Event }),
    getAccessToken: () => auth0Client?.getAccessToken({ event: h3Event }),
  };
};
