export default defineNuxtRouteMiddleware(async (to, from) => {
  if (import.meta.server) {
    const app = useNuxtApp();
    const h3Event = app.ssrContext!.event;
    const auth0Client = h3Event.context.auth0Client;

    const session = await auth0Client.getSession({ event: h3Event });

    useSession().value = session;
  }
});
